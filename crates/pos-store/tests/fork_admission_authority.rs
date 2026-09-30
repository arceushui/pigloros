use std::{
    error::Error,
    sync::{Arc, Barrier},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ciborium::value::Value;
use pos_core::ErasureInventoryPersistencePortV1 as _;
use pos_core::{
    clock::FixedAdmissionClock,
    fork_authentication::{
        principal_digest_v1, AuthenticatedPrincipalRecordV1, ForkAuthenticationAdapterPolicyV1,
        ForkAuthenticationPolicyV1,
    },
    CanonicalBytes, EntityId, ErasureContainmentGateV1, EventDraft, EventStore,
    ForkAdmissionCommandCodecErrorV1, ForkAdmissionHostCommandV1, ForkAdmissionOperationResultV1,
    ForkAdmissionRecoveryProofV1, Hash, Kind, PrincipalRefV1, PublicKey, Signature, TimelineId,
    WallTime,
};
use pos_crypto::fork_authentication::{
    verify_authenticated_principal_evidence_v1, ForkAuthenticationAdapterSigningKeyV1,
    ForkHostSigningKeyV1,
};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkAdmissionAuthorityBootstrapPortV1,
    ForkAdmissionAuthorityErrorV1, ForkAdmissionAuthorityPortV1, ForkAdmissionAuthoritySessionV1,
    ForkAdmissionDeliveryJournalPortV1, ForkDeliveryClaimOutcomeV1, ForkDeliveryClaimV1,
    ForkDeliveryExecutionV1, ForkDeliveryJournalErrorV1, ForkDeliveryStartupOutcomeV1,
    ForkDeliveryStateV1, ForkDeliveryTupleV1,
};
use rusqlite::{params, Connection};

const HOST_SEED: [u8; 32] = [7; 32];

/// ADR-106 r3: an admitted Fork needs an available bound erasure gate, so
/// Fork fixtures bind the open test gate (as `LedgerStore::fork` tests do).
fn bind_open_gate<S: EventStore>(store: &mut S) -> Result<(), Box<dyn Error>> {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    Ok(())
}
const POLICY_DIGEST: Hash = Hash::from_bytes([9; 32]);

fn bootstrap<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &mut S,
    signer: &ForkHostSigningKeyV1,
) -> Result<(), Box<dyn Error>> {
    let host_key = PublicKey::from_bytes(signer.public_key());
    let initialize = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let initialize_bytes = initialize.to_canonical_cbor()?;
    let initialize_signature = signer.sign_initialize(&initialize_bytes)?;
    let record = store.finalize_fork_admission_initialize(&initialize, &initialize_signature)?;
    assert_eq!(record.host_verifying_key(), host_key);
    assert_eq!(record.authentication_policy_digest(), POLICY_DIGEST);
    assert_eq!(
        store.begin_fork_admission_initialize(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized)
    );
    Ok(())
}

fn open_and_fence<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &mut S,
    signer: &ForkHostSigningKeyV1,
) -> Result<(), Box<dyn Error>> {
    let host_key = PublicKey::from_bytes(signer.public_key());
    let open = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let open_bytes = open.to_canonical_cbor()?;
    let open_signature = signer.sign_open(&open_bytes)?;
    let session = store.finalize_fork_admission_open(&open, &open_signature)?;
    store.advance_fork_admission_wall_fence(&session)?;
    assert!(matches!(
        store.finalize_fork_admission_open(&open, &open_signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    ));
    Ok(())
}

#[test]
fn public_session_identity_binds_complete_fao1_and_signature() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = MemoryStore::new();
    bootstrap(&mut store, &signer)?;
    let open = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_open(&open.canonical_bytes())?;
    let session = store.finalize_fork_admission_open(&open, &signature)?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/fork-admission-session/v1");
    hasher.update(&open.canonical_bytes());
    hasher.update(signature.as_bytes());
    assert_eq!(
        session.identity(),
        Hash::from_bytes(*hasher.finalize().as_bytes())
    );
    store.advance_fork_admission_wall_fence(&session)?;
    Ok(())
}

#[test]
fn memory_bootstrap_open_is_one_use_and_fenced() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let mut store = MemoryStore::new();
    bootstrap(&mut store, &signer)?;
    open_and_fence(&mut store, &signer)
}

#[test]
fn public_custom_clock_cannot_bootstrap_authority() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let mut store =
        MemoryStore::with_clock(Box::new(FixedAdmissionClock(WallTime::from_micros(1))));
    assert_eq!(
        store.begin_fork_admission_initialize(
            PublicKey::from_bytes(signer.public_key()),
            POLICY_DIGEST
        ),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
    );
    Ok(())
}

#[test]
fn public_delivery_tuple_constructor_fails_closed_and_preserves_values() {
    let host_request_id = Hash::from_bytes([1; 32]);
    let operation_id = Hash::from_bytes([2; 32]);
    let kind = pos_core::ForkAdmissionOperationKindV1::Fork;

    assert_eq!(
        ForkDeliveryTupleV1::new(Hash::zero(), kind, operation_id),
        Err(ForkDeliveryJournalErrorV1::InvalidTuple)
    );
    assert_eq!(
        ForkDeliveryTupleV1::new(host_request_id, kind, Hash::zero()),
        Err(ForkDeliveryJournalErrorV1::InvalidTuple)
    );
    assert_eq!(
        ForkDeliveryTupleV1::new(host_request_id, kind, operation_id),
        Ok(ForkDeliveryTupleV1 {
            host_request_id,
            kind,
            operation_id,
        })
    );
}

#[test]
fn sqlite_reopen_retains_host_and_fence() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    {
        let mut store = SqliteStore::open(&path)?;
        bootstrap(&mut store, &signer)?;
        open_and_fence(&mut store, &signer)?;
    }
    let mut reopened = SqliteStore::open(&path)?;
    assert_eq!(
        reopened
            .fork_admission_host_record()?
            .authentication_policy_digest(),
        POLICY_DIGEST
    );
    let host_key = PublicKey::from_bytes(signer.public_key());
    let open = reopened.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_open(&open.to_canonical_cbor()?)?;
    let session = reopened.finalize_fork_admission_open(&open, &signature)?;
    reopened.advance_fork_admission_wall_fence(&session)?;
    Ok(())
}

#[test]
fn rejected_initialize_consumes_the_issued_challenge() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = MemoryStore::new();
    let issued = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let substituted = pos_core::ForkAdmissionInitializeChallengeV1::new(
        Hash::from_bytes([8; 32]),
        issued.initialization_nonce(),
        host_key,
        POLICY_DIGEST,
    )?;
    let substitution_signature = signer.sign_initialize(&substituted.to_canonical_cbor()?)?;
    assert_eq!(
        store.finalize_fork_admission_initialize(&substituted, &substitution_signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    let valid_signature = signer.sign_initialize(&issued.to_canonical_cbor()?)?;
    assert_eq!(
        store.finalize_fork_admission_initialize(&issued, &valid_signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    Ok(())
}

#[test]
fn rejected_open_consumes_the_issued_challenge() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = MemoryStore::new();
    bootstrap(&mut store, &signer)?;
    let issued = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let substituted = pos_core::ForkAdmissionOpenChallengeV1::new(
        Hash::from_bytes([8; 32]),
        issued.open_nonce(),
        POLICY_DIGEST,
    )?;
    let substitution_signature = signer.sign_open(&substituted.to_canonical_cbor()?)?;
    assert!(matches!(
        store.finalize_fork_admission_open(&substituted, &substitution_signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    ));
    let valid_signature = signer.sign_open(&issued.to_canonical_cbor()?)?;
    assert!(matches!(
        store.finalize_fork_admission_open(&issued, &valid_signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    ));
    Ok(())
}

#[test]
fn sqlite_handle_cannot_consume_another_handles_challenge() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut issuer = SqliteStore::open(&path)?;
    let mut foreign = SqliteStore::open(&path)?;
    let challenge = issuer.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_initialize(&challenge.to_canonical_cbor()?)?;
    assert_eq!(
        foreign.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    issuer.finalize_fork_admission_initialize(&challenge, &signature)?;
    Ok(())
}

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn authority_policy(
    adapter: &ForkAuthenticationAdapterSigningKeyV1,
) -> Result<ForkAuthenticationPolicyV1, Box<dyn Error>> {
    Ok(ForkAuthenticationPolicyV1::new(vec![
        ForkAuthenticationAdapterPolicyV1 {
            adapter_id: "test-adapter".to_owned(),
            verifying_key: adapter.public_key(),
            minimum_assurance: 1,
            registry_bindings: vec![Hash::from_bytes([3; 32])],
        },
    ])?)
}

fn open_session<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &mut S,
    host: &ForkHostSigningKeyV1,
    policy: &ForkAuthenticationPolicyV1,
) -> Result<pos_store::ForkAdmissionAuthoritySessionV1, Box<dyn Error>> {
    let key = PublicKey::from_bytes(host.public_key());
    let initialize = store.begin_fork_admission_initialize(key, policy.digest()?)?;
    store.finalize_fork_admission_initialize(
        &initialize,
        &host.sign_initialize(&initialize.to_canonical_cbor()?)?,
    )?;
    let open = store.begin_fork_admission_open(key, policy.digest()?)?;
    Ok(store.finalize_fork_admission_open(&open, &host.sign_open(&open.to_canonical_cbor()?)?)?)
}

fn reopen_session<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &mut S,
    host: &ForkHostSigningKeyV1,
    policy: &ForkAuthenticationPolicyV1,
) -> Result<pos_store::ForkAdmissionAuthoritySessionV1, Box<dyn Error>> {
    let open = store
        .begin_fork_admission_open(PublicKey::from_bytes(host.public_key()), policy.digest()?)?;
    Ok(store.finalize_fork_admission_open(&open, &host.sign_open(&open.to_canonical_cbor()?)?)?)
}

fn principal_command<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &S,
    host: &ForkHostSigningKeyV1,
    adapter: &ForkAuthenticationAdapterSigningKeyV1,
    policy: &ForkAuthenticationPolicyV1,
    session: &pos_store::ForkAdmissionAuthoritySessionV1,
    operation_id: [u8; 32],
    expires_at: u64,
    owner: &str,
) -> Result<ForkAdmissionHostCommandV1, Box<dyn Error>> {
    let record = AuthenticatedPrincipalRecordV1 {
        principal: PrincipalRefV1::try_new([4; 16], "test.local")?,
        adapter_id: "test-adapter".to_owned(),
        assurance: 1,
        issued_at: 0,
        expires_at,
        registry_binding: Hash::from_bytes([3; 32]),
        operation_nonce: [5; 32],
    };
    let evidence = adapter.sign_authenticated_principal(record)?;
    let verified = verify_authenticated_principal_evidence_v1(policy, evidence)?;
    let principal = principal_digest_v1(&verified.evidence().record().principal)?;
    let inner = encode(&Value::Array(vec![
        Value::Text("POC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(
            store
                .fork_admission_host_record()?
                .store_id()
                .as_bytes()
                .to_vec(),
        ),
        Value::Bytes(session.identity().as_bytes().to_vec()),
        Value::Bytes(operation_id.to_vec()),
        Value::Bytes(verified.evidence().digest()?.as_bytes().to_vec()),
        Value::Bytes(principal.as_bytes().to_vec()),
        Value::Text(owner.to_owned()),
    ]))?;
    let signature = host.sign_command(&inner, &verified)?;
    let fac1 = encode(&Value::Array(vec![
        Value::Text("FAC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(inner),
        Value::Bytes(verified.evidence().to_canonical_cbor()?),
        Value::Bytes(signature.as_bytes().to_vec()),
    ]))?;
    Ok(ForkAdmissionHostCommandV1::from_canonical_cbor(&fac1)?)
}

fn recovery_proof<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &S,
    host: &ForkHostSigningKeyV1,
    session: &pos_store::ForkAdmissionAuthoritySessionV1,
    kind: u8,
    operation_id: [u8; 32],
) -> Result<ForkAdmissionRecoveryProofV1, Box<dyn Error>> {
    let recovery = encode(&Value::Array(vec![
        Value::Text("FRC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(
            store
                .fork_admission_host_record()?
                .store_id()
                .as_bytes()
                .to_vec(),
        ),
        Value::Bytes(session.identity().as_bytes().to_vec()),
        Value::Integer(kind.into()),
        Value::Bytes(operation_id.to_vec()),
    ]))?;
    let proof = encode(&Value::Array(vec![
        Value::Text("FRP1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(recovery.clone()),
        Value::Bytes(host.sign_recovery(&recovery)?.as_bytes().to_vec()),
    ]))?;
    Ok(ForkAdmissionRecoveryProofV1::from_canonical_cbor(&proof)?)
}

fn opaque_command(
    adapter: &ForkAuthenticationAdapterSigningKeyV1,
    policy: &ForkAuthenticationPolicyV1,
    command_bytes: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let evidence = adapter.sign_authenticated_principal(AuthenticatedPrincipalRecordV1 {
        principal: PrincipalRefV1::try_new([4; 16], "test.local")?,
        adapter_id: "test-adapter".to_owned(),
        assurance: 1,
        issued_at: 0,
        expires_at: u64::MAX,
        registry_binding: Hash::from_bytes([3; 32]),
        operation_nonce: [5; 32],
    })?;
    let verified = verify_authenticated_principal_evidence_v1(policy, evidence)?;
    let fac1 = encode(&Value::Array(vec![
        Value::Text("FAC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(command_bytes),
        Value::Bytes(verified.evidence().to_canonical_cbor()?),
        Value::Bytes(vec![0; 64]),
    ]))?;
    Ok(fac1)
}

fn opaque_recovery(recovery_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let proof = encode(&Value::Array(vec![
        Value::Text("FRP1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(recovery_bytes.to_vec()),
        Value::Bytes(vec![0; 64]),
    ]))?;
    Ok(proof)
}

fn sqlite_principal_recovery_fixture(
    path: &str,
    operation_id: [u8; 32],
) -> Result<
    (
        SqliteStore,
        ForkHostSigningKeyV1,
        pos_store::ForkAdmissionAuthoritySessionV1,
    ),
    Box<dyn Error>,
> {
    let host = ForkHostSigningKeyV1::from_seed([111; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([112; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(path)?;
    let session = open_session(&mut store, &host, &policy)?;
    let command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        operation_id,
        u64::MAX,
        "owner",
    )?;
    assert!(matches!(
        store.execute_fork_admission_command(&session, &policy, &command)?,
        ForkAdmissionOperationResultV1::PrincipalOwner(_)
    ));
    Ok((store, host, session))
}

fn claim_delivery<S: ForkAdmissionDeliveryJournalPortV1>(
    store: &mut S,
    session: &pos_store::ForkAdmissionAuthoritySessionV1,
    tuple: ForkDeliveryTupleV1,
    context: &str,
) -> Result<ForkDeliveryClaimV1, Box<dyn Error>> {
    match store.claim_fork_delivery(session, tuple)? {
        ForkDeliveryClaimOutcomeV1::Owner(claim) => Ok(claim),
        outcome => Err(std::io::Error::other(format!(
            "unexpected {context} delivery claim: {outcome:?}"
        ))
        .into()),
    }
}

fn assert_delivery_claim_is_fenced<S>(
    store: &mut S,
    session: &pos_store::ForkAdmissionAuthoritySessionV1,
    tuple: ForkDeliveryTupleV1,
    claim: ForkDeliveryClaimV1,
    host: &ForkHostSigningKeyV1,
    operation: [u8; 32],
) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionDeliveryJournalPortV1,
{
    assert_eq!(
        store.claim_fork_delivery(session, tuple)?,
        ForkDeliveryClaimOutcomeV1::Busy
    );
    let conflicting = ForkDeliveryTupleV1::new(
        tuple.host_request_id,
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([35; 32]),
    )?;
    assert_eq!(
        store.claim_fork_delivery(session, conflicting),
        Err(ForkDeliveryJournalErrorV1::Conflict)
    );
    assert_eq!(
        store.mark_fork_delivery_delivered(session, claim),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    assert_eq!(
        store.mark_fork_delivery_uncertain(session, claim),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    let pending_proof = recovery_proof(store, host, session, 1, operation)?;
    assert!(store
        .recover_fork_delivery(session, tuple, &pending_proof, Hash::from_bytes([4; 32]))
        .is_err());
    Ok(())
}

fn assert_absent_delivery_is_released<S>(
    store: &mut S,
    session: &pos_store::ForkAdmissionAuthoritySessionV1,
    host: &ForkHostSigningKeyV1,
) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionDeliveryJournalPortV1,
{
    let absent_operation = [50; 32];
    let absent_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([51; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(absent_operation),
    )?;
    let absent_claim = claim_delivery(store, session, absent_tuple, "absent-operation")?;
    let absent_proof = recovery_proof(store, host, session, 1, absent_operation)?;
    assert_eq!(
        store.reconcile_fork_delivery_startup(session, absent_tuple, &absent_proof)?,
        ForkDeliveryStartupOutcomeV1::ReleasedPending
    );
    let retry = claim_delivery(store, session, absent_tuple, "released retry")?;
    assert!(retry.owner_fence > absent_claim.owner_fence);
    store.cancel_pending_fork_delivery(session, retry)?;
    Ok(())
}

fn assert_delivery_journal<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1
        + ForkAdmissionAuthorityPortV1
        + ForkAdmissionDeliveryJournalPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([31; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([32; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut session = open_session(store, &host, &policy)?;
    let operation = [33; 32];
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([34; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(operation),
    )?;
    let claim = claim_delivery(store, &session, tuple, "first")?;
    assert_delivery_claim_is_fenced(store, &session, tuple, claim, &host, operation)?;
    let command = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        operation,
        u64::MAX,
        "delivery-owner",
    )?;
    assert!(matches!(
        store.execute_claimed_fork_delivery(&session, &policy, claim, &command)?,
        ForkDeliveryExecutionV1::Committed(_)
    ));
    store.mark_fork_delivery_uncertain(&session, claim)?;
    assert!(store
        .reconcile_fork_delivery_journal(&session)?
        .contains(&tuple));
    assert_eq!(
        store.claim_fork_delivery(&session, tuple)?,
        ForkDeliveryClaimOutcomeV1::Reconcile(claim, ForkDeliveryStateV1::Uncertain)
    );
    let proof = recovery_proof(store, &host, &session, 1, operation)?;
    assert_eq!(
        store.recover_fork_delivery(&session, tuple, &proof, Hash::from_bytes([36; 32])),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    let current_principal = principal_digest_v1(&PrincipalRefV1::try_new([4; 16], "test.local")?)?;
    assert!(matches!(
        store.recover_fork_delivery(&session, tuple, &proof, current_principal)?,
        ForkAdmissionOperationResultV1::PrincipalOwner(_)
    ));
    store.mark_fork_delivery_delivered(&session, claim)?;
    assert_eq!(
        store.reconcile_fork_delivery_startup(&session, tuple, &proof),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    assert_eq!(
        store.mark_fork_delivery_uncertain(&session, claim),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    assert_eq!(
        store.claim_fork_delivery(&session, tuple)?,
        ForkDeliveryClaimOutcomeV1::Reconcile(claim, ForkDeliveryStateV1::Delivered)
    );
    let next_session = reopen_session(store, &host, &policy)?;
    assert_eq!(
        store.recover_fork_delivery(&session, tuple, &proof, current_principal),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    session = next_session;
    let next_proof = recovery_proof(store, &host, &session, 1, operation)?;
    assert!(matches!(
        store.recover_fork_delivery(&session, tuple, &next_proof, current_principal)?,
        ForkAdmissionOperationResultV1::PrincipalOwner(_)
    ));
    store.purge_expired_fork_delivery(&session, tuple)?;
    let replacement = claim_delivery(store, &session, tuple, "replacement")?;
    assert!(replacement.owner_fence > claim.owner_fence);
    assert_eq!(
        store.mark_fork_delivery_uncertain(&session, claim),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    store.cancel_pending_fork_delivery(&session, replacement)?;
    let next = claim_delivery(store, &session, tuple, "post-cancel")?;
    assert!(next.owner_fence > replacement.owner_fence);
    assert_eq!(
        store.cancel_pending_fork_delivery(&session, replacement),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    assert_eq!(
        store.reconcile_fork_delivery_startup(&session, tuple, &next_proof)?,
        ForkDeliveryStartupOutcomeV1::RetainedUncertain
    );
    assert_eq!(
        store.claim_fork_delivery(&session, tuple)?,
        ForkDeliveryClaimOutcomeV1::Reconcile(next, ForkDeliveryStateV1::Uncertain)
    );
    assert_absent_delivery_is_released(store, &session, &host)
}

fn assert_delivery_journal_fences_stale_and_incomplete_work<S>(
    store: &mut S,
) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1
        + ForkAdmissionAuthorityPortV1
        + ForkAdmissionDeliveryJournalPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([61; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([62; 32])?;
    let policy = authority_policy(&adapter)?;
    let stale = open_session(store, &host, &policy)?;
    let session = reopen_session(store, &host, &policy)?;
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([63; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([64; 32]),
    )?;
    let claim = claim_delivery(store, &session, tuple, "incomplete")?;
    let command = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [64; 32],
        u64::MAX,
        "incomplete-owner",
    )?;
    let proof = recovery_proof(store, &host, &session, 1, [64; 32])?;

    assert!(store.claim_fork_delivery(&stale, tuple).is_err());
    assert!(store.cancel_pending_fork_delivery(&stale, claim).is_err());
    assert!(store
        .execute_claimed_fork_delivery(&stale, &policy, claim, &command)
        .is_err());
    assert!(store
        .recover_fork_delivery(&stale, tuple, &proof, Hash::from_bytes([65; 32]))
        .is_err());
    assert!(store.mark_fork_delivery_uncertain(&stale, claim).is_err());
    assert!(store.mark_fork_delivery_delivered(&stale, claim).is_err());
    assert!(store.reconcile_fork_delivery_journal(&stale).is_err());
    assert!(store
        .reconcile_fork_delivery_startup(&stale, tuple, &proof)
        .is_err());
    assert!(store.purge_expired_fork_delivery(&stale, tuple).is_err());

    assert!(store
        .recover_fork_delivery(&session, tuple, &proof, Hash::from_bytes([65; 32]))
        .is_err());
    assert!(store
        .execute_claimed_fork_delivery(
            &session,
            &policy,
            ForkDeliveryClaimV1 {
                owner_fence: claim.owner_fence + 1,
                ..claim
            },
            &command,
        )
        .is_err());
    assert!(store.purge_expired_fork_delivery(&session, tuple).is_err());

    let conflicting = ForkDeliveryTupleV1::new(
        Hash::from_bytes([66; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([64; 32]),
    )?;
    assert_eq!(
        store.claim_fork_delivery(&session, conflicting),
        Err(ForkDeliveryJournalErrorV1::Conflict)
    );
    let wrong_proof = recovery_proof(store, &host, &session, 1, [67; 32])?;
    assert_eq!(
        store.reconcile_fork_delivery_startup(&session, tuple, &wrong_proof),
        Err(ForkDeliveryJournalErrorV1::Conflict)
    );
    store.cancel_pending_fork_delivery(&session, claim)?;
    assert!(store.purge_expired_fork_delivery(&session, tuple).is_err());
    Ok(())
}

fn assert_delivery_rejects_mismatched_and_unauthenticated_commands<S>(
    store: &mut S,
) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1
        + ForkAdmissionAuthorityPortV1
        + ForkAdmissionDeliveryJournalPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;

    let mismatch_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([43; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([44; 32]),
    )?;
    let mismatch_claim = claim_delivery(store, &session, mismatch_tuple, "mismatch")?;
    let mismatched_command = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [45; 32],
        u64::MAX,
        "mismatch-owner",
    )?;
    assert_eq!(
        store.execute_claimed_fork_delivery(&session, &policy, mismatch_claim, &mismatched_command),
        Err(ForkDeliveryJournalErrorV1::Conflict)
    );
    store.cancel_pending_fork_delivery(&session, mismatch_claim)?;

    let rejected_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([46; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([47; 32]),
    )?;
    let rejected_claim = claim_delivery(store, &session, rejected_tuple, "expired")?;
    let expired_command = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [47; 32],
        1,
        "expired-owner",
    )?;
    assert!(matches!(
        store.execute_claimed_fork_delivery(&session, &policy, rejected_claim, &expired_command)?,
        ForkDeliveryExecutionV1::Rejected(pos_core::ForkAdmissionErrorV1::Unauthenticated)
    ));
    let retry = claim_delivery(store, &session, rejected_tuple, "expired retry")?;
    store.cancel_pending_fork_delivery(&session, retry)?;
    Ok(())
}

fn assert_fork_delivery_recovers_for_current_principal<S>(
    store: &mut S,
) -> Result<(), Box<dyn Error>>
where
    S: EventStore
        + ForkAdmissionAuthorityBootstrapPortV1
        + ForkAdmissionAuthorityPortV1
        + ForkAdmissionDeliveryJournalPortV1,
{
    bind_open_gate(store)?;
    let host = ForkHostSigningKeyV1::from_seed([51; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([52; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let owner = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [53; 32],
        u64::MAX,
        "fork-owner",
    )?;
    store.execute_fork_admission_command(&session, &policy, &owner)?;
    let parent = store.create_timeline("delivery-fork-parent")?;
    let operation = [54; 32];
    let command = fork_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        operation,
        parent.id(),
        "delivery-fork-child",
    )?;
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([55; 32]),
        pos_core::ForkAdmissionOperationKindV1::Fork,
        Hash::from_bytes(operation),
    )?;
    let claim = claim_delivery(store, &session, tuple, "fork")?;
    assert!(matches!(
        store.execute_claimed_fork_delivery(&session, &policy, claim, &command)?,
        ForkDeliveryExecutionV1::Committed(_)
    ));
    let proof = recovery_proof(store, &host, &session, 2, operation)?;
    let current_principal = principal_digest_v1(&PrincipalRefV1::try_new([4; 16], "test.local")?)?;
    assert!(matches!(
        store.recover_fork_delivery(&session, tuple, &proof, current_principal)?,
        ForkAdmissionOperationResultV1::Fork(_)
    ));
    assert_eq!(
        store.recover_fork_delivery(&session, tuple, &proof, Hash::from_bytes([56; 32])),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    let foreign_host = ForkHostSigningKeyV1::from_seed([57; 32])?;
    let foreign_proof = recovery_proof(store, &foreign_host, &session, 2, operation)?;
    assert_eq!(
        store.recover_fork_delivery(&session, tuple, &foreign_proof, current_principal),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    assert_eq!(
        store.reconcile_fork_delivery_startup(&session, tuple, &foreign_proof),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    Ok(())
}

#[test]
fn memory_delivery_journal_is_exact_fenced_and_principal_scoped() -> Result<(), Box<dyn Error>> {
    assert_delivery_journal(&mut MemoryStore::new())
}

#[test]
fn memory_delivery_journal_rejects_bad_commands_and_recovers_forks() -> Result<(), Box<dyn Error>> {
    assert_delivery_rejects_mismatched_and_unauthenticated_commands(&mut MemoryStore::new())?;
    assert_fork_delivery_recovers_for_current_principal(&mut MemoryStore::new())?;
    assert_delivery_journal_fences_stale_and_incomplete_work(&mut MemoryStore::new())
}

fn execution_label(
    outcome: &Result<ForkDeliveryExecutionV1, ForkDeliveryJournalErrorV1>,
) -> String {
    match outcome {
        Ok(ForkDeliveryExecutionV1::Committed(_)) => "Ok(Committed)".to_owned(),
        other => format!("{other:?}"),
    }
}

fn recovery_label(
    outcome: &Result<ForkAdmissionOperationResultV1, ForkDeliveryJournalErrorV1>,
) -> String {
    match outcome {
        Ok(ForkAdmissionOperationResultV1::PrincipalOwner(_)) => "Ok(PrincipalOwner)".to_owned(),
        Ok(ForkAdmissionOperationResultV1::Fork(_)) => "Ok(Fork)".to_owned(),
        Err(error) => format!("Err({error:?})"),
    }
}

struct DeliveryContractFixture {
    host: ForkHostSigningKeyV1,
    adapter: ForkAuthenticationAdapterSigningKeyV1,
    policy: ForkAuthenticationPolicyV1,
    session: pos_store::ForkAdmissionAuthoritySessionV1,
}

/// Zero digests and a definite FAC1 rejection, before any operation commits.
fn delivery_contract_rejections<S>(
    store: &mut S,
    fixture: &DeliveryContractFixture,
) -> Result<Vec<String>, Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1
        + ForkAdmissionAuthorityPortV1
        + ForkAdmissionDeliveryJournalPortV1,
{
    let session = &fixture.session;
    let operation = [148; 32];
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([149; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(operation),
    )?;
    let mut outcomes = Vec::new();
    // Public fields can bypass the constructor; the port still rejects zeros.
    for zero in [
        ForkDeliveryTupleV1 {
            host_request_id: Hash::zero(),
            ..tuple
        },
        ForkDeliveryTupleV1 {
            operation_id: Hash::zero(),
            ..tuple
        },
    ] {
        outcomes.push(format!("{:?}", store.claim_fork_delivery(session, zero)));
    }
    let claim = claim_delivery(store, session, tuple, "contract rejection")?;
    let expired = principal_command(
        store,
        &fixture.host,
        &fixture.adapter,
        &fixture.policy,
        session,
        operation,
        1,
        "contract-expired-owner",
    )?;
    outcomes.push(execution_label(&store.execute_claimed_fork_delivery(
        session,
        &fixture.policy,
        claim,
        &expired,
    )));
    outcomes.push(format!(
        "{:?}",
        store
            .claim_fork_delivery(session, tuple)
            .map(|outcome| matches!(outcome, ForkDeliveryClaimOutcomeV1::Owner(_)))
    ));
    Ok(outcomes)
}

/// Pending, mismatched, zero-principal, and committed recovery transitions.
fn delivery_contract_lifecycle<S>(
    store: &mut S,
    fixture: &DeliveryContractFixture,
) -> Result<Vec<String>, Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1
        + ForkAdmissionAuthorityPortV1
        + ForkAdmissionDeliveryJournalPortV1,
{
    let session = &fixture.session;
    let principal = principal_digest_v1(&PrincipalRefV1::try_new([4; 16], "test.local")?)?;
    let operation = [143; 32];
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([144; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(operation),
    )?;
    let mismatched = ForkDeliveryTupleV1 {
        operation_id: Hash::from_bytes([145; 32]),
        ..tuple
    };
    let absent = ForkDeliveryTupleV1::new(
        Hash::from_bytes([146; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([147; 32]),
    )?;
    let claim = claim_delivery(store, session, tuple, "contract lifecycle")?;
    let proof = recovery_proof(store, &fixture.host, session, 1, operation)?;
    let command = principal_command(
        store,
        &fixture.host,
        &fixture.adapter,
        &fixture.policy,
        session,
        operation,
        u64::MAX,
        "contract-owner",
    )?;
    Ok(vec![
        recovery_label(&store.recover_fork_delivery(session, tuple, &proof, principal)),
        recovery_label(&store.recover_fork_delivery(session, tuple, &proof, Hash::zero())),
        recovery_label(&store.recover_fork_delivery(session, mismatched, &proof, principal)),
        format!("{:?}", store.mark_fork_delivery_uncertain(session, claim)),
        format!("{:?}", store.purge_expired_fork_delivery(session, tuple)),
        format!("{:?}", store.purge_expired_fork_delivery(session, absent)),
        execution_label(&store.execute_claimed_fork_delivery(
            session,
            &fixture.policy,
            claim,
            &command,
        )),
        format!("{:?}", store.mark_fork_delivery_uncertain(session, claim)),
        recovery_label(&store.recover_fork_delivery(session, mismatched, &proof, principal)),
        recovery_label(&store.recover_fork_delivery(session, tuple, &proof, principal)),
    ])
}

fn delivery_contract_outcomes<S>(store: &mut S) -> Result<Vec<String>, Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1
        + ForkAdmissionAuthorityPortV1
        + ForkAdmissionDeliveryJournalPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([141; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([142; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let fixture = DeliveryContractFixture {
        host,
        adapter,
        policy,
        session,
    };
    let mut outcomes = delivery_contract_rejections(store, &fixture)?;
    outcomes.extend(delivery_contract_lifecycle(store, &fixture)?);
    let mut retained = store
        .reconcile_fork_delivery_journal(&fixture.session)?
        .iter()
        .map(|tuple| tuple.host_request_id.as_bytes()[0])
        .collect::<Vec<_>>();
    retained.sort_unstable();
    outcomes.push(format!("{retained:?}"));
    Ok(outcomes)
}

#[test]
fn delivery_journal_adapters_share_one_contract() -> Result<(), Box<dyn Error>> {
    let memory = delivery_contract_outcomes(&mut MemoryStore::new())?;
    let sqlite = delivery_contract_outcomes(&mut SqliteStore::open_in_memory()?)?;
    assert_eq!(memory, sqlite);
    assert_eq!(
        memory,
        [
            "Err(InvalidTuple)",
            "Err(InvalidTuple)",
            "Ok(Rejected(Unauthenticated))",
            "Ok(true)",
            "Err(Fenced)",
            "Err(InvalidTuple)",
            "Err(Conflict)",
            "Err(Fenced)",
            "Err(Fenced)",
            "Err(Fenced)",
            "Ok(Committed)",
            "Ok(())",
            "Err(Conflict)",
            "Ok(PrincipalOwner)",
            "[144, 149]",
        ]
    );
    Ok(())
}

#[test]
fn sqlite_delivery_journal_reopens_without_sensitive_columns() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-delivery.db");
    let path = path.to_string_lossy().into_owned();
    {
        let mut store = SqliteStore::open(&path)?;
        assert_delivery_journal(&mut store)?;
    }
    let connection = Connection::open(&path)?;
    let schema: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'fork_delivery_journal'",
        [],
        |row| row.get(0),
    )?;
    let schema = schema.to_ascii_lowercase();
    for forbidden in ["fal1", "farl1", "principal", "receipt", "result"] {
        assert!(
            !schema.contains(forbidden),
            "journal schema retained {forbidden}"
        );
    }
    drop(connection);
    let host = ForkHostSigningKeyV1::from_seed([31; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([32; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut reopened = SqliteStore::open(&path)?;
    let session = reopen_session(&mut reopened, &host, &policy)?;
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([34; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([33; 32]),
    )?;
    assert_eq!(
        reopened.reconcile_fork_delivery_journal(&session)?,
        vec![tuple]
    );
    let proof = recovery_proof(&reopened, &host, &session, 1, [33; 32])?;
    assert_eq!(
        reopened.reconcile_fork_delivery_startup(&session, tuple, &proof)?,
        ForkDeliveryStartupOutcomeV1::RetainedUncertain
    );
    let principal = principal_digest_v1(&PrincipalRefV1::try_new([4; 16], "test.local")?)?;
    assert!(matches!(
        reopened.recover_fork_delivery(&session, tuple, &proof, principal)?,
        ForkAdmissionOperationResultV1::PrincipalOwner(_)
    ));
    drop(reopened);
    let corrupt = Connection::open(&path)?;
    corrupt.execute(
        "UPDATE fork_delivery_journal SET operation_id = zeroblob(32) WHERE host_request_id = ?1",
        params![tuple.host_request_id.as_bytes().as_slice()],
    )?;
    drop(corrupt);
    let mut reopened = SqliteStore::open(&path)?;
    let session = reopen_session(&mut reopened, &host, &policy)?;
    assert!(reopened.reconcile_fork_delivery_journal(&session).is_err());
    Ok(())
}

#[test]
fn sqlite_delivery_journal_rejects_bad_commands_and_recovers_forks() -> Result<(), Box<dyn Error>> {
    assert_delivery_rejects_mismatched_and_unauthenticated_commands(
        &mut SqliteStore::open_in_memory()?,
    )?;
    assert_fork_delivery_recovers_for_current_principal(&mut SqliteStore::open_in_memory()?)?;
    assert_delivery_journal_fences_stale_and_incomplete_work(&mut SqliteStore::open_in_memory()?)
}

#[test]
fn sqlite_delivery_journal_rejects_malformed_retained_rows() -> Result<(), Box<dyn Error>> {
    for update in [
        "UPDATE fork_delivery_journal SET kind = 3",
        "UPDATE fork_delivery_journal SET host_request_id = X'00'",
        "UPDATE fork_delivery_journal SET operation_id = X'00'",
        "UPDATE fork_delivery_journal SET operation_id = zeroblob(32)",
        "UPDATE fork_delivery_journal SET state = 4",
        "UPDATE fork_delivery_journal SET owner_fence = 0",
        "UPDATE fork_delivery_journal SET owner_fence = -1",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("malformed-delivery.db");
        let path = path.to_string_lossy().into_owned();
        let host = ForkHostSigningKeyV1::from_seed([71; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([72; 32])?;
        let policy = authority_policy(&adapter)?;
        let tuple = ForkDeliveryTupleV1::new(
            Hash::from_bytes([73; 32]),
            pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
            Hash::from_bytes([77; 32]),
        )?;
        {
            let mut store = SqliteStore::open(&path)?;
            let session = open_session(&mut store, &host, &policy)?;
            claim_delivery(&mut store, &session, tuple, "malformed retained row")?;
        }
        let connection = Connection::open(&path)?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
        connection.execute(update, [])?;
        drop(connection);

        let mut reopened = SqliteStore::open(&path)?;
        let session = reopen_session(&mut reopened, &host, &policy)?;
        assert_eq!(
            reopened.reconcile_fork_delivery_journal(&session),
            Err(ForkDeliveryJournalErrorV1::Corrupt)
        );
    }
    Ok(())
}

#[test]
fn sqlite_delivery_journal_rejects_untyped_retained_columns() -> Result<(), Box<dyn Error>> {
    for update in [
        "UPDATE fork_delivery_journal SET kind = 'wrong-kind'",
        "UPDATE fork_delivery_journal SET operation_id = 'wrong-operation'",
        "UPDATE fork_delivery_journal SET state = 'wrong-state'",
        "UPDATE fork_delivery_journal SET owner_fence = 'wrong-fence'",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("untyped-delivery.db");
        let path = path.to_string_lossy().into_owned();
        let host = ForkHostSigningKeyV1::from_seed([106; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([107; 32])?;
        let policy = authority_policy(&adapter)?;
        let tuple = ForkDeliveryTupleV1::new(
            Hash::from_bytes([108; 32]),
            pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
            Hash::from_bytes([109; 32]),
        )?;
        let mut store = SqliteStore::open(&path)?;
        let session = open_session(&mut store, &host, &policy)?;
        claim_delivery(&mut store, &session, tuple, "untyped retained row")?;
        let connection = Connection::open(&path)?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
        connection.execute(update, [])?;
        assert_eq!(
            store.reconcile_fork_delivery_journal(&session),
            Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
        );
    }
    Ok(())
}

#[test]
fn sqlite_delivery_scan_omits_valid_delivered_rows_but_validates_them() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("delivered-delivery.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([78; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([79; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(&path)?;
    let session = open_session(&mut store, &host, &policy)?;
    let operation = [80; 32];
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([81; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(operation),
    )?;
    let claim = claim_delivery(&mut store, &session, tuple, "delivered scan")?;
    let command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        operation,
        u64::MAX,
        "delivered-scan-owner",
    )?;
    assert!(matches!(
        store.execute_claimed_fork_delivery(&session, &policy, claim, &command)?,
        ForkDeliveryExecutionV1::Committed(_)
    ));
    store.mark_fork_delivery_delivered(&session, claim)?;
    assert!(store.reconcile_fork_delivery_journal(&session)?.is_empty());

    let corrupt = Connection::open(&path)?;
    corrupt.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    corrupt.execute(
        "UPDATE fork_delivery_journal SET owner_fence = 0 WHERE host_request_id = ?1",
        params![tuple.host_request_id.as_bytes().as_slice()],
    )?;
    drop(corrupt);
    assert_eq!(
        store.reconcile_fork_delivery_journal(&session),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    Ok(())
}

#[test]
fn sqlite_delivery_journal_reconciles_and_purges_only_the_exact_delivered_tuple(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("delivered-reconciliation.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([89; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([90; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(&path)?;
    let session = open_session(&mut store, &host, &policy)?;
    let operation = [91; 32];
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([92; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(operation),
    )?;
    let claim = claim_delivery(&mut store, &session, tuple, "delivered reconciliation")?;
    let command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        operation,
        u64::MAX,
        "delivered-reconciliation-owner",
    )?;
    assert!(matches!(
        store.execute_claimed_fork_delivery(&session, &policy, claim, &command)?,
        ForkDeliveryExecutionV1::Committed(_)
    ));
    store.mark_fork_delivery_delivered(&session, claim)?;
    assert_eq!(
        store.claim_fork_delivery(&session, tuple)?,
        ForkDeliveryClaimOutcomeV1::Reconcile(claim, ForkDeliveryStateV1::Delivered)
    );
    let conflicting = ForkDeliveryTupleV1::new(
        tuple.host_request_id,
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([93; 32]),
    )?;
    assert_eq!(
        store.purge_expired_fork_delivery(&session, conflicting),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    store.purge_expired_fork_delivery(&session, tuple)?;
    let next_claim = claim_delivery(&mut store, &session, tuple, "purged tuple")?;
    assert_eq!(next_claim.owner_fence, claim.owner_fence + 1);
    Ok(())
}

#[test]
fn sqlite_delivery_journal_fails_closed_for_corrupt_and_stale_retained_rows(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("corrupt-and-stale-delivery.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([94; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([95; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(&path)?;
    let session = open_session(&mut store, &host, &policy)?;
    let operation = [96; 32];
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([97; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(operation),
    )?;
    let claim = claim_delivery(&mut store, &session, tuple, "stale retained row")?;
    let command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        operation,
        u64::MAX,
        "stale-retained-owner",
    )?;
    let proof = recovery_proof(&store, &host, &session, 1, operation)?;
    let mismatched_tuple = ForkDeliveryTupleV1::new(
        tuple.host_request_id,
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([98; 32]),
    )?;
    assert_eq!(
        store.recover_fork_delivery(
            &session,
            mismatched_tuple,
            &proof,
            Hash::from_bytes([99; 32])
        ),
        Err(ForkDeliveryJournalErrorV1::Conflict)
    );
    assert!(matches!(
        store.execute_claimed_fork_delivery(&session, &policy, claim, &command)?,
        ForkDeliveryExecutionV1::Committed(_)
    ));
    let wrong_proof = recovery_proof(&store, &host, &session, 1, [100; 32])?;
    assert_eq!(
        store.recover_fork_delivery(&session, tuple, &wrong_proof, Hash::from_bytes([99; 32])),
        Err(ForkDeliveryJournalErrorV1::Conflict)
    );
    assert_eq!(
        store.recover_fork_delivery(&session, tuple, &proof, Hash::zero()),
        Err(ForkDeliveryJournalErrorV1::InvalidTuple)
    );
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_delivery_journal SET owner_fence = owner_fence + 1 WHERE host_request_id = ?1",
        params![tuple.host_request_id.as_bytes().as_slice()],
    )?;
    assert_eq!(
        store.cancel_pending_fork_delivery(&session, claim),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    assert_eq!(
        store.mark_fork_delivery_uncertain(&session, claim),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    assert_eq!(
        store.execute_claimed_fork_delivery(&session, &policy, claim, &command),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    connection.execute(
        "UPDATE fork_delivery_journal SET owner_fence = 0 WHERE host_request_id = ?1",
        params![tuple.host_request_id.as_bytes().as_slice()],
    )?;
    assert_eq!(
        store.claim_fork_delivery(&session, tuple),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    Ok(())
}

#[test]
fn sqlite_delivery_execution_fences_missing_and_malformed_journal_rows(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("delivery-execution-rows.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([101; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([102; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(&path)?;
    let session = open_session(&mut store, &host, &policy)?;
    let operation = [103; 32];
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([104; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(operation),
    )?;
    let claim = claim_delivery(&mut store, &session, tuple, "missing execution row")?;
    let command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        operation,
        u64::MAX,
        "missing-execution-row-owner",
    )?;
    let proof = recovery_proof(&store, &host, &session, 1, operation)?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "DELETE FROM fork_delivery_journal WHERE host_request_id = ?1",
        params![tuple.host_request_id.as_bytes().as_slice()],
    )?;
    assert_eq!(
        store.execute_claimed_fork_delivery(&session, &policy, claim, &command),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    assert_eq!(
        store.recover_fork_delivery(&session, tuple, &proof, Hash::from_bytes([105; 32])),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    assert_eq!(
        store.reconcile_fork_delivery_startup(&session, tuple, &proof),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );

    let retry = claim_delivery(&mut store, &session, tuple, "malformed execution row")?;
    connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    connection.execute(
        "UPDATE fork_delivery_journal SET kind = 3 WHERE host_request_id = ?1",
        params![tuple.host_request_id.as_bytes().as_slice()],
    )?;
    assert_eq!(
        store.execute_claimed_fork_delivery(&session, &policy, retry, &command),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    Ok(())
}

#[test]
fn sqlite_startup_reconciliation_rejects_an_uncertain_delivery_without_operation(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("missing-delivery-operation.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([91; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([92; 32])?;
    let policy = authority_policy(&adapter)?;
    let operation = [93; 32];
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([94; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(operation),
    )?;
    {
        let mut store = SqliteStore::open(&path)?;
        let session = open_session(&mut store, &host, &policy)?;
        let claim = claim_delivery(&mut store, &session, tuple, "missing operation")?;
        let command = principal_command(
            &store,
            &host,
            &adapter,
            &policy,
            &session,
            operation,
            u64::MAX,
            "missing-operation-owner",
        )?;
        assert!(matches!(
            store.execute_claimed_fork_delivery(&session, &policy, claim, &command)?,
            ForkDeliveryExecutionV1::Committed(_)
        ));
    }
    let corrupt = Connection::open(&path)?;
    assert_eq!(
        corrupt.execute(
            "DELETE FROM fork_admission_operations WHERE kind = ?1 AND operation_id = ?2",
            params![1_i64, tuple.operation_id.as_bytes().as_slice()],
        )?,
        1
    );
    drop(corrupt);

    let mut reopened = SqliteStore::open(&path)?;
    let session = reopen_session(&mut reopened, &host, &policy)?;
    assert_eq!(
        reopened.reconcile_fork_delivery_journal(&session)?,
        vec![tuple]
    );
    let proof = recovery_proof(&reopened, &host, &session, 1, operation)?;
    assert_eq!(
        reopened.reconcile_fork_delivery_startup(&session, tuple, &proof),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    Ok(())
}

#[test]
fn sqlite_delivery_claim_has_one_owner_across_concurrent_handles() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("concurrent-delivery.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([31; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([32; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut first = SqliteStore::open(&path)?;
    let first_session = open_session(&mut first, &host, &policy)?;
    let mut second = SqliteStore::open(&path)?;
    let second_session = reopen_session(&mut second, &host, &policy)?;
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([61; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([62; 32]),
    )?;
    let barrier = Arc::new(Barrier::new(2));
    let first_barrier = Arc::clone(&barrier);
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first.claim_fork_delivery(&first_session, tuple)
    });
    let second_thread = std::thread::spawn(move || {
        barrier.wait();
        second.claim_fork_delivery(&second_session, tuple)
    });
    let first_outcome = first_thread
        .join()
        .map_err(|_| std::io::Error::other("first claim panicked"))?;
    let second_outcome = second_thread
        .join()
        .map_err(|_| std::io::Error::other("second claim panicked"))?;
    let outcomes = [first_outcome, second_outcome];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ForkDeliveryClaimOutcomeV1::Owner(_))))
            .count(),
        1
    );
    assert!(outcomes.iter().all(|outcome| matches!(
        outcome,
        Ok(ForkDeliveryClaimOutcomeV1::Owner(_) | ForkDeliveryClaimOutcomeV1::Busy)
            | Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    )));
    Ok(())
}

#[test]
fn sqlite_delivery_claim_rolls_back_fence_when_insert_fails() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("rollback-delivery.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([31; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([32; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(&path)?;
    let session = open_session(&mut store, &host, &policy)?;
    let first_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([71; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([72; 32]),
    )?;
    let first = claim_delivery(&mut store, &session, first_tuple, "first")?;
    store.cancel_pending_fork_delivery(&session, first)?;
    let failing = Connection::open(&path)?;
    failing.execute_batch("CREATE TRIGGER reject_delivery_insert BEFORE INSERT ON fork_delivery_journal BEGIN SELECT RAISE(ABORT, 'injected insert failure'); END")?;
    let next_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([73; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([74; 32]),
    )?;
    // A non-UNIQUE insert failure is an indeterminate write, not a tuple conflict.
    assert_eq!(
        store.claim_fork_delivery(&session, next_tuple),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    failing.execute_batch("DROP TRIGGER reject_delivery_insert")?;
    let next = claim_delivery(&mut store, &session, next_tuple, "post-rollback")?;
    assert_eq!(next.owner_fence, first.owner_fence + 1);
    failing.execute_batch(
        "UPDATE fork_delivery_fence_counter SET last_fence = 9223372036854775807 WHERE id = 1",
    )?;
    let exhausted_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([75; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([76; 32]),
    )?;
    assert_eq!(
        store.claim_fork_delivery(&session, exhausted_tuple),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    Ok(())
}

struct SqliteDeliveryFaultContext {
    _directory: tempfile::TempDir,
    host: ForkHostSigningKeyV1,
    adapter: ForkAuthenticationAdapterSigningKeyV1,
    policy: ForkAuthenticationPolicyV1,
    store: SqliteStore,
    session: pos_store::ForkAdmissionAuthoritySessionV1,
    fault: Connection,
}

fn sqlite_delivery_fault_context() -> Result<SqliteDeliveryFaultContext, Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("delivery-write-faults.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([81; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([82; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(&path)?;
    let session = open_session(&mut store, &host, &policy)?;
    let fault = Connection::open(&path)?;
    Ok(SqliteDeliveryFaultContext {
        _directory: directory,
        host,
        adapter,
        policy,
        store,
        session,
        fault,
    })
}

#[test]
fn sqlite_delivery_journal_claim_fence_faults() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    fault.execute_batch("BEGIN EXCLUSIVE")?;
    let locked_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([83; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([84; 32]),
    )?;
    assert_eq!(
        store.claim_fork_delivery(&session, locked_tuple),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    fault.execute_batch("ROLLBACK")?;

    let counter_update_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([96; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([97; 32]),
    )?;
    fault.execute_batch(
        "CREATE TRIGGER reject_delivery_fence_counter_update BEFORE UPDATE ON fork_delivery_fence_counter BEGIN SELECT RAISE(ABORT, 'injected delivery fence counter update failure'); END",
    )?;
    assert_eq!(
        store.claim_fork_delivery(&session, counter_update_tuple),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    fault.execute_batch("DROP TRIGGER reject_delivery_fence_counter_update")?;

    let counter_read_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([98; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([99; 32]),
    )?;
    fault.execute_batch(
        "CREATE TRIGGER remove_delivery_fence_counter AFTER UPDATE ON fork_delivery_fence_counter BEGIN DELETE FROM fork_delivery_fence_counter WHERE id = 1; END",
    )?;
    assert_eq!(
        store.claim_fork_delivery(&session, counter_read_tuple),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    fault.execute_batch("DROP TRIGGER remove_delivery_fence_counter")?;

    Ok(())
}

#[test]
fn sqlite_delivery_claim_refuses_negative_persisted_fence() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    fault.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    assert_eq!(
        fault.execute(
            "UPDATE fork_delivery_fence_counter SET last_fence = -1 WHERE id = 1",
            [],
        )?,
        1
    );
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([100; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([101; 32]),
    )?;
    assert_eq!(
        store.claim_fork_delivery(&session, tuple),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    Ok(())
}

#[test]
fn sqlite_delivery_reconciliation_rejects_corrupt_journal_fence() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([102; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([103; 32]),
    )?;
    claim_delivery(&mut store, &session, tuple, "corrupt reconciliation row")?;
    fault.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    assert_eq!(
        fault.execute(
            "UPDATE fork_delivery_journal SET owner_fence = -1 WHERE host_request_id = ?1",
            params![tuple.host_request_id.as_bytes().as_slice()],
        )?,
        1
    );
    assert_eq!(
        store.reconcile_fork_delivery_journal(&session),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    Ok(())
}

#[test]
fn sqlite_delivery_recovery_rejects_corrupt_journal_row() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        host,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    let operation = [104; 32];
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([105; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(operation),
    )?;
    claim_delivery(&mut store, &session, tuple, "corrupt recovery row")?;
    let proof = recovery_proof(&store, &host, &session, 1, operation)?;
    fault.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    assert_eq!(
        fault.execute(
            "UPDATE fork_delivery_journal SET operation_id = zeroblob(31) WHERE host_request_id = ?1",
            params![tuple.host_request_id.as_bytes().as_slice()],
        )?,
        1
    );
    assert_eq!(
        store.recover_fork_delivery(&session, tuple, &proof, Hash::from_bytes([106; 32])),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    Ok(())
}

#[test]
fn sqlite_delivery_startup_rejects_corrupt_journal_row() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        host,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    let operation = [107; 32];
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([108; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(operation),
    )?;
    claim_delivery(&mut store, &session, tuple, "corrupt startup row")?;
    let proof = recovery_proof(&store, &host, &session, 1, operation)?;
    fault.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    assert_eq!(
        fault.execute(
            "UPDATE fork_delivery_journal SET state = 0 WHERE host_request_id = ?1",
            params![tuple.host_request_id.as_bytes().as_slice()],
        )?,
        1
    );
    assert_eq!(
        store.reconcile_fork_delivery_startup(&session, tuple, &proof),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    Ok(())
}

#[test]
fn sqlite_delivery_execution_begin_and_rejection_delete_faults() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        host,
        adapter,
        policy,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    let begin_operation = [110; 32];
    let begin_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([111; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(begin_operation),
    )?;
    let begin_claim = claim_delivery(&mut store, &session, begin_tuple, "execution begin fault")?;
    let begin_command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        begin_operation,
        u64::MAX,
        "execution-begin-fault-owner",
    )?;
    fault.execute_batch("BEGIN EXCLUSIVE")?;
    assert_eq!(
        store.execute_claimed_fork_delivery(&session, &policy, begin_claim, &begin_command),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    fault.execute_batch("ROLLBACK")?;
    store.cancel_pending_fork_delivery(&session, begin_claim)?;

    let rejection_operation = [112; 32];
    let rejection_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([113; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(rejection_operation),
    )?;
    let rejection_claim = claim_delivery(
        &mut store,
        &session,
        rejection_tuple,
        "rejection delete fault",
    )?;
    let expired_command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        rejection_operation,
        1,
        "rejection-delete-fault-owner",
    )?;
    fault.execute_batch(
        "CREATE TRIGGER reject_execution_rejection_delete BEFORE DELETE ON fork_delivery_journal BEGIN SELECT RAISE(ABORT, 'injected execution rejection delete failure'); END",
    )?;
    assert_eq!(
        store.execute_claimed_fork_delivery(
            &session,
            &policy,
            rejection_claim,
            &expired_command
        )?,
        ForkDeliveryExecutionV1::Uncertain
    );
    fault.execute_batch("DROP TRIGGER reject_execution_rejection_delete")?;
    assert_eq!(
        store.claim_fork_delivery(&session, rejection_tuple)?,
        ForkDeliveryClaimOutcomeV1::Reconcile(rejection_claim, ForkDeliveryStateV1::Uncertain)
    );
    Ok(())
}

#[test]
fn sqlite_delivery_journal_admission_write_fault() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        host,
        adapter,
        policy,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    let uncertain_operation = [84; 32];
    let uncertain_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([85; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(uncertain_operation),
    )?;
    let uncertain_claim = claim_delivery(
        &mut store,
        &session,
        uncertain_tuple,
        "admission write fault",
    )?;
    let uncertain_command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        uncertain_operation,
        u64::MAX,
        "admission-write-fault-owner",
    )?;
    fault.execute_batch(
        "CREATE TRIGGER reject_admission_operation_insert BEFORE INSERT ON fork_admission_operations BEGIN SELECT RAISE(ABORT, 'injected admission operation insert failure'); END",
    )?;
    assert_eq!(
        store.execute_claimed_fork_delivery(
            &session,
            &policy,
            uncertain_claim,
            &uncertain_command
        )?,
        ForkDeliveryExecutionV1::Uncertain
    );
    fault.execute_batch("DROP TRIGGER reject_admission_operation_insert")?;
    assert_eq!(
        store.claim_fork_delivery(&session, uncertain_tuple)?,
        ForkDeliveryClaimOutcomeV1::Reconcile(uncertain_claim, ForkDeliveryStateV1::Uncertain)
    );
    store.mark_fork_delivery_delivered(&session, uncertain_claim)?;
    store.purge_expired_fork_delivery(&session, uncertain_tuple)?;

    Ok(())
}

#[test]
fn sqlite_delivery_recovery_fails_closed_for_invalid_proofs_and_missing_operations(
) -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        host,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    let wrong_host = ForkHostSigningKeyV1::from_seed([115; 32])?;
    let invalid_proof_operation = [116; 32];
    let invalid_proof_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([117; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(invalid_proof_operation),
    )?;
    claim_delivery(
        &mut store,
        &session,
        invalid_proof_tuple,
        "invalid recovery proof",
    )?;
    assert_eq!(
        fault.execute(
            "UPDATE fork_delivery_journal SET state = 2 WHERE host_request_id = ?1",
            params![invalid_proof_tuple.host_request_id.as_bytes().as_slice()],
        )?,
        1
    );
    let invalid_proof = recovery_proof(&store, &wrong_host, &session, 1, invalid_proof_operation)?;
    assert_eq!(
        store.recover_fork_delivery(
            &session,
            invalid_proof_tuple,
            &invalid_proof,
            Hash::from_bytes([118; 32]),
        ),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );

    let missing_operation = [119; 32];
    let missing_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([120; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(missing_operation),
    )?;
    claim_delivery(
        &mut store,
        &session,
        missing_tuple,
        "missing recovery operation",
    )?;
    assert_eq!(
        fault.execute(
            "UPDATE fork_delivery_journal SET state = 2 WHERE host_request_id = ?1",
            params![missing_tuple.host_request_id.as_bytes().as_slice()],
        )?,
        1
    );
    let missing_proof = recovery_proof(&store, &host, &session, 1, missing_operation)?;
    assert_eq!(
        store.recover_fork_delivery(
            &session,
            missing_tuple,
            &missing_proof,
            Hash::from_bytes([121; 32]),
        ),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );

    Ok(())
}

#[test]
fn sqlite_delivery_startup_rejects_invalid_proofs_and_lock_contention() -> Result<(), Box<dyn Error>>
{
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        host,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    let wrong_host = ForkHostSigningKeyV1::from_seed([115; 32])?;

    let startup_invalid_proof_operation = [122; 32];
    let startup_invalid_proof_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([123; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(startup_invalid_proof_operation),
    )?;
    let startup_invalid_proof_claim = claim_delivery(
        &mut store,
        &session,
        startup_invalid_proof_tuple,
        "invalid startup proof",
    )?;
    let startup_invalid_proof = recovery_proof(
        &store,
        &wrong_host,
        &session,
        1,
        startup_invalid_proof_operation,
    )?;
    assert_eq!(
        store.reconcile_fork_delivery_startup(
            &session,
            startup_invalid_proof_tuple,
            &startup_invalid_proof,
        ),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    store.cancel_pending_fork_delivery(&session, startup_invalid_proof_claim)?;

    let startup_lock_operation = [124; 32];
    let startup_lock_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([125; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(startup_lock_operation),
    )?;
    let startup_lock_claim =
        claim_delivery(&mut store, &session, startup_lock_tuple, "startup lock")?;
    let startup_lock_proof = recovery_proof(&store, &host, &session, 1, startup_lock_operation)?;
    fault.execute_batch("BEGIN IMMEDIATE")?;
    assert_eq!(
        store.reconcile_fork_delivery_startup(&session, startup_lock_tuple, &startup_lock_proof),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    fault.execute_batch("ROLLBACK")?;
    store.cancel_pending_fork_delivery(&session, startup_lock_claim)?;

    Ok(())
}

#[test]
fn sqlite_delivery_startup_rejects_corrupt_operation_row() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        host,
        adapter,
        policy,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    let corrupt_operation = [126; 32];
    let corrupt_operation_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([127; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(corrupt_operation),
    )?;
    let corrupt_operation_command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        corrupt_operation,
        u64::MAX,
        "corrupt-startup-operation-owner",
    )?;
    store.execute_fork_admission_command(&session, &policy, &corrupt_operation_command)?;
    claim_delivery(
        &mut store,
        &session,
        corrupt_operation_tuple,
        "corrupt startup operation",
    )?;
    let corrupt_operation_proof = recovery_proof(&store, &host, &session, 1, corrupt_operation)?;
    assert_eq!(
        fault.execute(
            "UPDATE fork_admission_operations SET child_id = 'not-a-timeline-id' WHERE kind = ?1 AND operation_id = ?2",
            params![1_i64, corrupt_operation_tuple.operation_id.as_bytes().as_slice()],
        )?,
        1
    );
    assert_eq!(
        store.reconcile_fork_delivery_startup(
            &session,
            corrupt_operation_tuple,
            &corrupt_operation_proof,
        ),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );

    Ok(())
}

#[test]
fn sqlite_delivery_startup_rejects_corrupt_result_row() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        host,
        adapter,
        policy,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;

    let corrupt_result = [128; 32];
    let corrupt_result_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([129; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(corrupt_result),
    )?;
    let corrupt_result_command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        corrupt_result,
        u64::MAX,
        "corrupt-startup-result-owner",
    )?;
    store.execute_fork_admission_command(&session, &policy, &corrupt_result_command)?;
    claim_delivery(
        &mut store,
        &session,
        corrupt_result_tuple,
        "corrupt startup result",
    )?;
    let corrupt_result_proof = recovery_proof(&store, &host, &session, 1, corrupt_result)?;
    assert_eq!(
        fault.execute(
            "UPDATE fork_admission_operations SET result_digest = zeroblob(32) WHERE kind = ?1 AND operation_id = ?2",
            params![1_i64, corrupt_result_tuple.operation_id.as_bytes().as_slice()],
        )?,
        1
    );
    assert_eq!(
        store.reconcile_fork_delivery_startup(
            &session,
            corrupt_result_tuple,
            &corrupt_result_proof,
        ),
        Err(ForkDeliveryJournalErrorV1::Corrupt)
    );
    Ok(())
}

#[test]
fn sqlite_delivery_journal_startup_faults() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        host,
        adapter,
        policy,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    let startup_operation = [86; 32];
    let startup_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([87; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(startup_operation),
    )?;
    let startup_claim = claim_delivery(&mut store, &session, startup_tuple, "startup delete race")?;
    let startup_proof = recovery_proof(&store, &host, &session, 1, startup_operation)?;
    fault.execute_batch(
        "CREATE TRIGGER remove_pending_delivery_before_startup_delete BEFORE DELETE ON fork_delivery_journal BEGIN DELETE FROM fork_delivery_journal WHERE host_request_id = OLD.host_request_id; END",
    )?;
    assert_eq!(
        store.reconcile_fork_delivery_startup(&session, startup_tuple, &startup_proof),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    fault.execute_batch("DROP TRIGGER remove_pending_delivery_before_startup_delete")?;
    store.cancel_pending_fork_delivery(&session, startup_claim)?;

    let rejected_delete_operation = [130; 32];
    let rejected_delete_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([131; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(rejected_delete_operation),
    )?;
    let rejected_delete_claim = claim_delivery(
        &mut store,
        &session,
        rejected_delete_tuple,
        "startup delete rejection",
    )?;
    let rejected_delete_proof =
        recovery_proof(&store, &host, &session, 1, rejected_delete_operation)?;
    fault.execute_batch(
        "CREATE TRIGGER reject_startup_delivery_delete BEFORE DELETE ON fork_delivery_journal BEGIN SELECT RAISE(ABORT, 'injected startup delivery delete failure'); END",
    )?;
    assert_eq!(
        store.reconcile_fork_delivery_startup(
            &session,
            rejected_delete_tuple,
            &rejected_delete_proof,
        ),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    fault.execute_batch("DROP TRIGGER reject_startup_delivery_delete")?;
    store.cancel_pending_fork_delivery(&session, rejected_delete_claim)?;

    let startup_state_operation = [92; 32];
    let startup_state_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([93; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(startup_state_operation),
    )?;
    let startup_state_command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        startup_state_operation,
        u64::MAX,
        "startup-state-write-fault-owner",
    )?;
    store.execute_fork_admission_command(&session, &policy, &startup_state_command)?;
    let startup_state_claim = claim_delivery(
        &mut store,
        &session,
        startup_state_tuple,
        "startup state write fault",
    )?;
    let startup_state_proof = recovery_proof(&store, &host, &session, 1, startup_state_operation)?;
    fault.execute_batch(
        "CREATE TRIGGER reject_startup_delivery_state_update BEFORE UPDATE OF state ON fork_delivery_journal BEGIN SELECT RAISE(ABORT, 'injected startup delivery state update failure'); END",
    )?;
    assert_eq!(
        store.reconcile_fork_delivery_startup(&session, startup_state_tuple, &startup_state_proof),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    fault.execute_batch("DROP TRIGGER reject_startup_delivery_state_update")?;
    store.cancel_pending_fork_delivery(&session, startup_state_claim)?;

    Ok(())
}

#[test]
fn sqlite_delivery_journal_state_and_delete_faults() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        host,
        adapter,
        policy,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    let operation = [88; 32];
    let tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([89; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(operation),
    )?;
    let claim = claim_delivery(&mut store, &session, tuple, "state write fault")?;
    let command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        operation,
        u64::MAX,
        "write-fault-owner",
    )?;
    fault.execute_batch(
        "CREATE TRIGGER reject_delivery_state_update BEFORE UPDATE OF state ON fork_delivery_journal BEGIN SELECT RAISE(ABORT, 'injected state update failure'); END",
    )?;
    assert_eq!(
        store.execute_claimed_fork_delivery(&session, &policy, claim, &command),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    fault.execute_batch("DROP TRIGGER reject_delivery_state_update")?;
    store.cancel_pending_fork_delivery(&session, claim)?;

    let delete_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([90; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes([91; 32]),
    )?;
    let delete_claim = claim_delivery(&mut store, &session, delete_tuple, "delete write fault")?;
    fault.execute_batch(
        "CREATE TRIGGER reject_delivery_delete BEFORE DELETE ON fork_delivery_journal BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END",
    )?;
    assert_eq!(
        store.cancel_pending_fork_delivery(&session, delete_claim),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    fault.execute_batch("DROP TRIGGER reject_delivery_delete")?;
    store.cancel_pending_fork_delivery(&session, delete_claim)?;

    let out_of_range_claim = ForkDeliveryClaimV1 {
        owner_fence: u64::MAX,
        ..delete_claim
    };
    assert_eq!(
        store.cancel_pending_fork_delivery(&session, out_of_range_claim),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    assert_eq!(
        store.mark_fork_delivery_uncertain(&session, out_of_range_claim),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    assert_eq!(
        store.mark_fork_delivery_delivered(&session, out_of_range_claim),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );
    assert_eq!(
        store.execute_claimed_fork_delivery(
            &session,
            &policy,
            ForkDeliveryClaimV1 {
                owner_fence: u64::MAX,
                ..claim
            },
            &command,
        ),
        Err(ForkDeliveryJournalErrorV1::Fenced)
    );

    Ok(())
}

#[test]
fn sqlite_delivery_journal_purge_fault() -> Result<(), Box<dyn Error>> {
    let SqliteDeliveryFaultContext {
        _directory: _directory_guard,
        host,
        adapter,
        policy,
        mut store,
        session,
        fault,
        ..
    } = sqlite_delivery_fault_context()?;
    let purge_operation = [94; 32];
    let purge_tuple = ForkDeliveryTupleV1::new(
        Hash::from_bytes([95; 32]),
        pos_core::ForkAdmissionOperationKindV1::PrincipalOwner,
        Hash::from_bytes(purge_operation),
    )?;
    let purge_claim = claim_delivery(&mut store, &session, purge_tuple, "purge write fault")?;
    let purge_command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        purge_operation,
        u64::MAX,
        "purge-write-fault-owner",
    )?;
    assert!(matches!(
        store.execute_claimed_fork_delivery(&session, &policy, purge_claim, &purge_command)?,
        ForkDeliveryExecutionV1::Committed(_)
    ));
    store.mark_fork_delivery_delivered(&session, purge_claim)?;
    fault.execute_batch(
        "CREATE TRIGGER reject_delivery_purge BEFORE DELETE ON fork_delivery_journal BEGIN SELECT RAISE(ABORT, 'injected delivery purge failure'); END",
    )?;
    assert_eq!(
        store.purge_expired_fork_delivery(&session, purge_tuple),
        Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
    );
    fault.execute_batch("DROP TRIGGER reject_delivery_purge")?;
    store.purge_expired_fork_delivery(&session, purge_tuple)?;
    Ok(())
}

fn fork_command<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &S,
    host: &ForkHostSigningKeyV1,
    adapter: &ForkAuthenticationAdapterSigningKeyV1,
    policy: &ForkAuthenticationPolicyV1,
    session: &pos_store::ForkAdmissionAuthoritySessionV1,
    operation_id: [u8; 32],
    parent: TimelineId,
    child_name: &str,
) -> Result<ForkAdmissionHostCommandV1, Box<dyn Error>> {
    let record = AuthenticatedPrincipalRecordV1 {
        principal: PrincipalRefV1::try_new([4; 16], "test.local")?,
        adapter_id: "test-adapter".to_owned(),
        assurance: 1,
        issued_at: 0,
        expires_at: u64::MAX,
        registry_binding: Hash::from_bytes([3; 32]),
        operation_nonce: [5; 32],
    };
    let evidence = adapter.sign_authenticated_principal(record)?;
    let verified = verify_authenticated_principal_evidence_v1(policy, evidence)?;
    let principal = principal_digest_v1(&verified.evidence().record().principal)?;
    let inner = encode(&Value::Array(vec![
        Value::Text("FCC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(
            store
                .fork_admission_host_record()?
                .store_id()
                .as_bytes()
                .to_vec(),
        ),
        Value::Bytes(session.identity().as_bytes().to_vec()),
        Value::Bytes(operation_id.to_vec()),
        Value::Bytes(verified.evidence().digest()?.as_bytes().to_vec()),
        Value::Bytes(principal.as_bytes().to_vec()),
        Value::Bytes(parent.inner().to_bytes().to_vec()),
        Value::Integer(0.into()),
        Value::Integer(0.into()),
        Value::Bytes(vec![8; 32]),
        Value::Bytes(vec![9; 32]),
        Value::Integer(1.into()),
        Value::Text(child_name.to_owned()),
    ]))?;
    let signature = host.sign_command(&inner, &verified)?;
    let fac1 = encode(&Value::Array(vec![
        Value::Text("FAC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(inner),
        Value::Bytes(verified.evidence().to_canonical_cbor()?),
        Value::Bytes(signature.as_bytes().to_vec()),
    ]))?;
    Ok(ForkAdmissionHostCommandV1::from_canonical_cbor(&fac1)?)
}

type SqliteForkRecoveryFixture = (
    SqliteStore,
    ForkHostSigningKeyV1,
    ForkAuthenticationPolicyV1,
    pos_store::ForkAdmissionAuthoritySessionV1,
    TimelineId,
);

fn sqlite_fork_recovery_fixture(
    path: &str,
    parent_name: &str,
    child_name: &str,
) -> Result<SqliteForkRecoveryFixture, Box<dyn Error>> {
    let host = ForkHostSigningKeyV1::from_seed([51; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([52; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(path)?;
    bind_open_gate(&mut store)?;
    let session = open_session(&mut store, &host, &policy)?;
    let principal = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        [53; 32],
        u64::MAX,
        "owner",
    )?;
    store.execute_fork_admission_command(&session, &policy, &principal)?;
    let parent = store.create_timeline(parent_name)?;
    let command = fork_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        [54; 32],
        parent.id(),
        child_name,
    )?;
    let ForkAdmissionOperationResultV1::Fork(receipt) =
        store.execute_fork_admission_command(&session, &policy, &command)?
    else {
        return Err("FCC1 did not return a FAR1 receipt".into());
    };
    Ok((store, host, policy, session, receipt.child_id))
}

fn assert_fac1_and_recovery<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([11; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([12; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let current_session = {
        let key = PublicKey::from_bytes(host.public_key());
        let open = store.begin_fork_admission_open(key, policy.digest()?)?;
        store.finalize_fork_admission_open(&open, &host.sign_open(&open.to_canonical_cbor()?)?)?
    };
    let command = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &current_session,
        [6; 32],
        u64::MAX,
        "owner",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );
    assert!(matches!(
        store.execute_fork_admission_command(&current_session, &policy, &command)?,
        ForkAdmissionOperationResultV1::PrincipalOwner(_)
    ));
    assert!(matches!(
        store.execute_fork_admission_command(&current_session, &policy, &command)?,
        ForkAdmissionOperationResultV1::PrincipalOwner(_)
    ));
    let proof = recovery_proof(store, &host, &current_session, 1, [6; 32])?;
    assert!(matches!(
        store.recover_fork_admission_command(&current_session, &proof,)?,
        ForkAdmissionOperationResultV1::PrincipalOwner(_)
    ));
    let wrong_kind = recovery_proof(store, &host, &current_session, 2, [6; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&current_session, &wrong_kind),
        Err(pos_core::ForkAdmissionErrorV1::OperationMissing)
    );
    Ok(())
}

fn assert_fcc1_and_atomic_recovery<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1 + EventStore,
{
    bind_open_gate(store)?;
    let host = ForkHostSigningKeyV1::from_seed([21; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([22; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let principal = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [23; 32],
        u64::MAX,
        "owner",
    )?;
    assert!(matches!(
        store.execute_fork_admission_command(&session, &policy, &principal)?,
        ForkAdmissionOperationResultV1::PrincipalOwner(_)
    ));
    let parent = store.create_timeline("fac1-parent")?;
    let command = fork_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [24; 32],
        parent.id(),
        "fac1-child",
    )?;
    let result = store.execute_fork_admission_command(&session, &policy, &command)?;
    let ForkAdmissionOperationResultV1::Fork(receipt) = result else {
        return Err("FCC1 did not return a FAR1 receipt".into());
    };
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &command)?,
        ForkAdmissionOperationResultV1::Fork(receipt),
        "an exact FCC1 retry resolves to the committed FAR1 receipt"
    );
    let recovery = recovery_proof(store, &host, &session, 2, [24; 32])?;
    assert!(matches!(
        store.recover_fork_admission_command(&session, &recovery)?,
        ForkAdmissionOperationResultV1::Fork(recovered)
            if recovered == receipt
    ));
    let conflict = fork_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [24; 32],
        parent.id(),
        "different-child",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &conflict),
        Err(pos_core::ForkAdmissionErrorV1::Conflict)
    );
    let missing_parent = fork_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [25; 32],
        TimelineId::new(),
        "missing-parent",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &missing_parent),
        Err(pos_core::ForkAdmissionErrorV1::ParentChanged)
    );
    let missing_recovery = recovery_proof(store, &host, &session, 2, [25; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &missing_recovery),
        Err(pos_core::ForkAdmissionErrorV1::OperationMissing)
    );
    Ok(())
}

fn assert_expired_fac1_leaves_no_operation<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([31; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([32; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let expired = principal_command(
        store, &host, &adapter, &policy, &session, [33; 32], 1, "owner",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &expired),
        Err(pos_core::ForkAdmissionErrorV1::Unauthenticated)
    );
    let recovery = recovery_proof(store, &host, &session, 1, [33; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &recovery),
        Err(pos_core::ForkAdmissionErrorV1::OperationMissing)
    );
    let valid = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [33; 32],
        u64::MAX,
        "owner",
    )?;
    assert!(matches!(
        store.execute_fork_admission_command(&session, &policy, &valid)?,
        ForkAdmissionOperationResultV1::PrincipalOwner(_)
    ));
    Ok(())
}

fn assert_tampered_fac1_is_rejected<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([34; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([35; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let command = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [36; 32],
        u64::MAX,
        "owner",
    )?;
    let mut bytes = command.to_canonical_cbor();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let tampered = ForkAdmissionHostCommandV1::from_canonical_cbor(&bytes)?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &tampered),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );
    let recovery = recovery_proof(store, &host, &session, 1, [36; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &recovery),
        Err(pos_core::ForkAdmissionErrorV1::OperationMissing)
    );
    Ok(())
}

fn assert_principal_owner_binding_is_unique<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([35; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([36; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let first = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [37; 32],
        u64::MAX,
        "owner",
    )?;
    assert!(matches!(
        store.execute_fork_admission_command(&session, &policy, &first)?,
        ForkAdmissionOperationResultV1::PrincipalOwner(_)
    ));
    let duplicate_principal = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [38; 32],
        u64::MAX,
        "other-owner",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &duplicate_principal),
        Err(pos_core::ForkAdmissionErrorV1::PrincipalOwnerConflict)
    );
    Ok(())
}

fn assert_pinned_policy_is_required<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([39; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([40; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let command = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [41; 32],
        u64::MAX,
        "owner",
    )?;
    let substituted_policy =
        ForkAuthenticationPolicyV1::new(vec![ForkAuthenticationAdapterPolicyV1 {
            adapter_id: "test-adapter".to_owned(),
            verifying_key: adapter.public_key(),
            minimum_assurance: 1,
            registry_bindings: vec![Hash::from_bytes([4; 32])],
        }])?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &substituted_policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );
    Ok(())
}

fn assert_stale_fold_boundary_is_rejected<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1 + EventStore,
{
    let host = ForkHostSigningKeyV1::from_seed([43; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([44; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let principal = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [45; 32],
        u64::MAX,
        "owner",
    )?;
    store.execute_fork_admission_command(&session, &policy, &principal)?;
    let parent = store.create_timeline("stale-fold-parent")?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let entity = EntityId::new();
    store.append(
        parent.id(),
        &[
            EventDraft::new(
                entity,
                Kind::new("fork.admission.coverage"),
                CanonicalBytes::from_vec(b"first".to_vec()),
            ),
            EventDraft::new(
                entity,
                Kind::new("fork.admission.coverage"),
                CanonicalBytes::from_vec(b"second".to_vec()),
            ),
        ],
    )?;
    let command = fork_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [46; 32],
        parent.id(),
        "stale-fold-child",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::StaleFoldBoundary)
    );
    Ok(())
}

fn rejects_mismatched_open_and_consumes_bad_proof<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &mut S,
    signer: &ForkHostSigningKeyV1,
) -> Result<(), Box<dyn Error>> {
    bootstrap(store, signer)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    assert_eq!(
        store.begin_fork_admission_open(host_key, Hash::from_bytes([8; 32])),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    let challenge = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    assert!(matches!(
        store.finalize_fork_admission_open(&challenge, &Signature::from_bytes([0; 64])),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    ));
    let signature = signer.sign_open(&challenge.to_canonical_cbor()?)?;
    assert!(matches!(
        store.finalize_fork_admission_open(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    ));
    Ok(())
}

#[test]
fn memory_open_rejects_mismatch_and_bad_proof() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let mut store = MemoryStore::new();
    rejects_mismatched_open_and_consumes_bad_proof(&mut store, &signer)
}

#[test]
fn sqlite_open_rejects_mismatch_and_bad_proof() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let mut store = SqliteStore::open(&path.to_string_lossy())?;
    rejects_mismatched_open_and_consumes_bad_proof(&mut store, &signer)
}

#[test]
fn sqlite_authority_lifecycle_rejects_corruption_and_stale_sessions() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = SqliteStore::open(&path)?;
    bootstrap(&mut store, &signer)?;

    let first = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let first_signature = signer.sign_open(&first.to_canonical_cbor()?)?;
    let first_session = store.finalize_fork_admission_open(&first, &first_signature)?;
    let second = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let second_signature = signer.sign_open(&second.to_canonical_cbor()?)?;
    let second_session = store.finalize_fork_admission_open(&second, &second_signature)?;
    assert_eq!(
        store.advance_fork_admission_wall_fence(&first_session),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    store.advance_fork_admission_wall_fence(&second_session)?;
    drop(store);

    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_authority SET fah1_cbor = X'00' WHERE singleton = 1",
        [],
    )?;
    drop(connection);
    let store = SqliteStore::open(&path)?;
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    drop(store);

    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_authority SET fah1_cbor = NULL, last_authority_wall_time = -1 \
         WHERE singleton = 1",
        [],
    )?;
    drop(connection);
    let store = SqliteStore::open(&path)?;
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_authority_finalize_rolls_back_a_rejected_durable_host_write() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = SqliteStore::open(&path)?;
    let challenge = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_initialize(&challenge.to_canonical_cbor()?)?;
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TRIGGER reject_fork_admission_insert
         BEFORE INSERT ON fork_admission_authority
         BEGIN SELECT RAISE(ABORT, 'rejected'); END;",
    )?;
    drop(connection);

    assert_eq!(
        store.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::StorageIndeterminate)
    );
    drop(store);

    let connection = Connection::open(&path)?;
    connection.execute_batch("DROP TRIGGER reject_fork_admission_insert")?;
    drop(connection);
    let mut reopened = SqliteStore::open(&path)?;
    let retry = reopened.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let retry_signature = signer.sign_initialize(&retry.to_canonical_cbor()?)?;
    reopened.finalize_fork_admission_initialize(&retry, &retry_signature)?;
    Ok(())
}

#[test]
fn public_authority_paths_fail_closed_without_a_production_clock() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let initialize = pos_core::ForkAdmissionInitializeChallengeV1::new(
        Hash::from_bytes([1; 32]),
        Hash::from_bytes([2; 32]),
        host_key,
        POLICY_DIGEST,
    )?;
    let initialize_signature = signer.sign_initialize(&initialize.canonical_bytes())?;
    let open = pos_core::ForkAdmissionOpenChallengeV1::new(
        Hash::from_bytes([1; 32]),
        Hash::from_bytes([2; 32]),
        POLICY_DIGEST,
    )?;
    let open_signature = signer.sign_open(&open.canonical_bytes())?;
    let mut disabled =
        MemoryStore::with_clock(Box::new(FixedAdmissionClock(WallTime::from_micros(1))));
    assert_eq!(
        disabled.finalize_fork_admission_initialize(&initialize, &initialize_signature),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
    );
    assert_eq!(
        disabled.begin_fork_admission_open(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
    );
    assert!(matches!(
        disabled.finalize_fork_admission_open(&open, &open_signature),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
    ));

    let mut enabled = MemoryStore::new();
    bootstrap(&mut enabled, &signer)?;
    let challenge = enabled.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let session = enabled.finalize_fork_admission_open(
        &challenge,
        &signer.sign_open(&challenge.canonical_bytes())?,
    )?;
    assert_eq!(
        disabled.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
    );
    Ok(())
}

#[test]
fn public_authority_paths_reject_missing_state_and_clock_rollback() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut empty = MemoryStore::new();
    assert_eq!(
        empty.begin_fork_admission_open(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)
    );
    let open = pos_core::ForkAdmissionOpenChallengeV1::new(
        Hash::from_bytes([1; 32]),
        Hash::from_bytes([2; 32]),
        POLICY_DIGEST,
    )?;
    assert!(matches!(
        empty.finalize_fork_admission_open(&open, &signer.sign_open(&open.canonical_bytes())?),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)
    ));

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    bootstrap(&mut store, &signer)?;
    let challenge = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let session = store.finalize_fork_admission_open(
        &challenge,
        &signer.sign_open(&challenge.canonical_bytes())?,
    )?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_authority SET last_authority_wall_time = ?1 WHERE singleton = 1",
        [i64::MAX],
    )?;
    drop(connection);
    assert_eq!(
        store.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::ClockRollback)
    );
    Ok(())
}

#[test]
fn sqlite_authority_methods_fail_closed_when_durable_state_is_unreadable(
) -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    bootstrap(&mut store, &signer)?;
    let open = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let session =
        store.finalize_fork_admission_open(&open, &signer.sign_open(&open.canonical_bytes())?)?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_authority SET fah1_cbor = 1 WHERE singleton = 1",
        [],
    )?;
    drop(connection);
    assert_eq!(
        store.begin_fork_admission_open(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    assert!(matches!(
        store.finalize_fork_admission_open(&open, &signer.sign_open(&open.canonical_bytes())?),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    ));
    assert_eq!(
        store.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_authority_initialize_paths_fail_closed_on_durable_state_errors(
) -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    let challenge = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "INSERT INTO fork_admission_authority (singleton, fah1_cbor, last_authority_wall_time) \
         VALUES (1, 1, 0)",
        [],
    )?;
    drop(connection);
    assert_eq!(
        store.begin_fork_admission_initialize(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    assert_eq!(
        store.finalize_fork_admission_initialize(
            &challenge,
            &signer.sign_initialize(&challenge.canonical_bytes())?
        ),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn public_authority_bootstrap_rejects_invalid_inputs_and_reused_initialization(
) -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = MemoryStore::new();

    assert_eq!(
        store.begin_fork_admission_initialize(PublicKey::from_bytes([0; 32]), POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    let challenge = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_initialize(&challenge.canonical_bytes())?;
    store.finalize_fork_admission_initialize(&challenge, &signature)?;
    assert_eq!(
        store.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized)
    );

    let mut rejected = MemoryStore::new();
    let challenge = rejected.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    assert_eq!(
        rejected.finalize_fork_admission_initialize(&challenge, &Signature::from_bytes([0; 64])),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    Ok(())
}

#[test]
fn public_authority_fence_rejects_empty_and_unopened_sessions() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut issuer = MemoryStore::new();
    bootstrap(&mut issuer, &signer)?;
    let challenge = issuer.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let session = issuer.finalize_fork_admission_open(
        &challenge,
        &signer.sign_open(&challenge.canonical_bytes())?,
    )?;

    let mut empty = MemoryStore::new();
    assert_eq!(
        empty.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)
    );

    let mut unopened = MemoryStore::new();
    bootstrap(&mut unopened, &signer)?;
    assert_eq!(
        unopened.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    Ok(())
}

#[test]
fn sqlite_authority_fails_closed_for_malformed_rows_and_lock_contention(
) -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    bootstrap(&mut store, &signer)?;
    drop(store);

    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_authority SET last_authority_wall_time = 'not-an-integer' \
         WHERE singleton = 1",
        [],
    )?;
    drop(connection);
    let store = SqliteStore::open(&path)?;
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    drop(store);

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-lock.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    let lock = Connection::open(&path)?;
    lock.execute_batch("BEGIN EXCLUSIVE")?;
    assert_eq!(
        store.begin_fork_admission_initialize(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::StorageIndeterminate)
    );
    lock.execute_batch("ROLLBACK")?;
    Ok(())
}

#[test]
fn memory_fac1_commits_pob1_and_rejects_a_copied_identity_without_its_session(
) -> Result<(), Box<dyn Error>> {
    assert_fac1_and_recovery(&mut MemoryStore::new())
}

#[test]
fn sqlite_fac1_and_frp1_match_the_public_memory_contract() -> Result<(), Box<dyn Error>> {
    assert_fac1_and_recovery(&mut SqliteStore::open_in_memory()?)
}

#[test]
fn memory_fcc1_commits_far1_and_rolls_back_rejected_operations() -> Result<(), Box<dyn Error>> {
    assert_fcc1_and_atomic_recovery(&mut MemoryStore::new())
}

#[test]
fn sqlite_fcc1_commits_far1_and_rolls_back_rejected_operations() -> Result<(), Box<dyn Error>> {
    assert_fcc1_and_atomic_recovery(&mut SqliteStore::open_in_memory()?)
}

#[test]
fn sqlite_file_backed_concurrent_first_use_commits_one_principal_binding(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("concurrent-fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([61; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([62; 32])?;
    let policy = authority_policy(&adapter)?;
    {
        let mut store = SqliteStore::open(&path)?;
        open_session(&mut store, &host, &policy)?;
    }

    let mut first_store = SqliteStore::open(&path)?;
    let first_session = reopen_session(&mut first_store, &host, &policy)?;
    let first_command = principal_command(
        &first_store,
        &host,
        &adapter,
        &policy,
        &first_session,
        [63; 32],
        u64::MAX,
        "owner",
    )?;
    let mut second_store = SqliteStore::open(&path)?;
    let second_session = reopen_session(&mut second_store, &host, &policy)?;
    let second_command = principal_command(
        &second_store,
        &host,
        &adapter,
        &policy,
        &second_session,
        [64; 32],
        u64::MAX,
        "other-owner",
    )?;

    let barrier = Arc::new(Barrier::new(2));
    let execute = |mut store: SqliteStore,
                   session,
                   policy: ForkAuthenticationPolicyV1,
                   command,
                   barrier: Arc<Barrier>| {
        std::thread::spawn(move || {
            barrier.wait();
            match store.execute_fork_admission_command(&session, &policy, &command) {
                Ok(ForkAdmissionOperationResultV1::PrincipalOwner(_)) => Ok(true),
                Err(pos_core::ForkAdmissionErrorV1::PrincipalOwnerConflict) => Ok(false),
                result => Err(format!(
                    "unexpected concurrent first-use result: {result:?}"
                )),
            }
        })
    };
    let first_thread = execute(
        first_store,
        first_session,
        policy.clone(),
        first_command,
        Arc::clone(&barrier),
    );
    let second_thread = execute(
        second_store,
        second_session,
        policy,
        second_command,
        barrier,
    );
    let first = first_thread
        .join()
        .map_err(|_| std::io::Error::other("first concurrent command thread failed"))?
        .map_err(std::io::Error::other)?;
    let second = second_thread
        .join()
        .map_err(|_| std::io::Error::other("second concurrent command thread failed"))?
        .map_err(std::io::Error::other)?;
    assert_ne!(first, second);

    let connection = Connection::open(&path)?;
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM fork_principal_owner_bindings",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        1
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM fork_admission_operations WHERE kind = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        1
    );
    Ok(())
}

#[test]
fn sqlite_file_backed_failed_fork_transaction_leaves_zero_partial_graph(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("atomic-fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([71; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([72; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(&path)?;
    bind_open_gate(&mut store)?;
    let session = open_session(&mut store, &host, &policy)?;
    let principal = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        [73; 32],
        u64::MAX,
        "owner",
    )?;
    store.execute_fork_admission_command(&session, &policy, &principal)?;
    let parent = store.create_timeline("atomic-parent")?;
    let command = fork_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        [74; 32],
        parent.id(),
        "atomic-child",
    )?;
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TRIGGER reject_fork_operation
         BEFORE INSERT ON fork_admission_operations
         WHEN NEW.kind = 2
         BEGIN SELECT RAISE(ABORT, 'rejected'); END;",
    )?;
    drop(connection);
    // Re-establish the bound gate's durable snapshot after the external write.
    store.complete_erasure_inventory_snapshot(1)?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::StorageIndeterminate)
    );
    drop(store);

    let connection = Connection::open(&path)?;
    for query in [
        "SELECT COUNT(*) FROM fork_admissions",
        "SELECT COUNT(*) FROM fork_admission_operations WHERE kind = 2",
        "SELECT COUNT(*) FROM timelines WHERE name = 'atomic-child'",
    ] {
        assert_eq!(
            connection.query_row(query, [], |row| row.get::<_, i64>(0))?,
            0
        );
    }
    Ok(())
}

#[test]
fn sqlite_fac1_maps_durable_authority_and_write_faults() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-authority-fault.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([141; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([142; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(&path)?;
    let session = open_session(&mut store, &host, &policy)?;
    let command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        [143; 32],
        u64::MAX,
        "owner",
    )?;
    let recovery = recovery_proof(&store, &host, &session, 1, [143; 32])?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_authority SET fah1_cbor = X'00' WHERE singleton = 1",
        [],
    )?;
    drop(connection);
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    assert_eq!(
        store.recover_fork_admission_command(&session, &recovery),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    drop(store);

    for (name, fault) in [
        ("operation-read", "DROP TABLE fork_admission_operations;"),
        ("binding-read", "DROP TABLE fork_principal_owner_bindings;"),
        (
            "binding-write",
            "CREATE TRIGGER reject_principal_binding
             BEFORE INSERT ON fork_principal_owner_bindings
             BEGIN SELECT RAISE(ABORT, 'rejected'); END;",
        ),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join(format!("fork-admission-{name}.db"));
        let path = path.to_string_lossy().into_owned();
        let host = ForkHostSigningKeyV1::from_seed([144; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([145; 32])?;
        let policy = authority_policy(&adapter)?;
        let mut store = SqliteStore::open(&path)?;
        let session = open_session(&mut store, &host, &policy)?;
        let command = principal_command(
            &store,
            &host,
            &adapter,
            &policy,
            &session,
            [146; 32],
            u64::MAX,
            "owner",
        )?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(fault)?;
        drop(connection);
        assert_eq!(
            store.execute_fork_admission_command(&session, &policy, &command),
            Err(pos_core::ForkAdmissionErrorV1::StorageIndeterminate),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn sqlite_fcc1_maps_child_and_admission_write_faults() -> Result<(), Box<dyn Error>> {
    for (name, fault) in [
        (
            "child",
            "CREATE TRIGGER reject_fork_child
             BEFORE INSERT ON timelines
             WHEN NEW.parent_id IS NOT NULL
             BEGIN SELECT RAISE(ABORT, 'rejected'); END;",
        ),
        (
            "admission",
            "CREATE TRIGGER reject_fork_admission
             BEFORE INSERT ON fork_admissions
             BEGIN SELECT RAISE(ABORT, 'rejected'); END;",
        ),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join(format!("fork-admission-{name}-write.db"));
        let path = path.to_string_lossy().into_owned();
        let host = ForkHostSigningKeyV1::from_seed([151; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([152; 32])?;
        let policy = authority_policy(&adapter)?;
        let mut store = SqliteStore::open(&path)?;
        bind_open_gate(&mut store)?;
        let session = open_session(&mut store, &host, &policy)?;
        let principal = principal_command(
            &store,
            &host,
            &adapter,
            &policy,
            &session,
            [153; 32],
            u64::MAX,
            "owner",
        )?;
        store.execute_fork_admission_command(&session, &policy, &principal)?;
        let parent = store.create_timeline("fault-parent")?;
        let command = fork_command(
            &store,
            &host,
            &adapter,
            &policy,
            &session,
            [154; 32],
            parent.id(),
            "fault-child",
        )?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(fault)?;
        drop(connection);
        store.complete_erasure_inventory_snapshot(1)?;
        assert_eq!(
            store.execute_fork_admission_command(&session, &policy, &command),
            Err(pos_core::ForkAdmissionErrorV1::StorageIndeterminate),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn sqlite_open_rejects_incompatible_fork_admission_graph_schemas() -> Result<(), Box<dyn Error>> {
    for (name, schema) in [
        (
            "bindings",
            "DROP TABLE fork_principal_owner_bindings;
             CREATE TABLE fork_principal_owner_bindings (operation_id BLOB PRIMARY KEY);",
        ),
        (
            "admissions",
            "DROP TABLE fork_admissions;
             CREATE TABLE fork_admissions (child_id TEXT PRIMARY KEY);",
        ),
        (
            "operations",
            "DROP TABLE fork_admission_operations;
             CREATE TABLE fork_admission_operations (kind INTEGER, operation_id BLOB);",
        ),
        (
            "classifier-sources",
            "DROP TABLE fork_classifier_sources;
             CREATE TABLE fork_classifier_sources (descriptor_hash BLOB PRIMARY KEY);",
        ),
        (
            "classifier-tables",
            "DROP TABLE fork_classifier_tables;
             CREATE TABLE fork_classifier_tables (child_id TEXT PRIMARY KEY);",
        ),
        (
            "classifier-registrations",
            "DROP TABLE fork_classifier_registrations;
             CREATE TABLE fork_classifier_registrations (operation_id BLOB PRIMARY KEY);",
        ),
        (
            "event-origins",
            "DROP TABLE fork_event_origins;
             CREATE TABLE fork_event_origins (event_id TEXT PRIMARY KEY);",
        ),
        (
            "intervention-admissions",
            "DROP TABLE fork_intervention_admissions;
             CREATE TABLE fork_intervention_admissions (event_id TEXT PRIMARY KEY);",
        ),
        (
            "append-operations",
            "DROP TABLE fork_append_operations;
             CREATE TABLE fork_append_operations (operation_id BLOB PRIMARY KEY);",
        ),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join(format!("{name}.db"));
        SqliteStore::open(&path.to_string_lossy())?;
        Connection::open(&path)?.execute_batch(schema)?;
        assert!(SqliteStore::open(&path.to_string_lossy()).is_err());
    }
    Ok(())
}

#[test]
fn memory_expired_fac1_is_not_recoverable() -> Result<(), Box<dyn Error>> {
    assert_expired_fac1_leaves_no_operation(&mut MemoryStore::new())
}

#[test]
fn sqlite_expired_fac1_is_not_recoverable() -> Result<(), Box<dyn Error>> {
    assert_expired_fac1_leaves_no_operation(&mut SqliteStore::open_in_memory()?)
}

#[test]
fn memory_rejects_a_tampered_fac1_without_persisting_an_operation() -> Result<(), Box<dyn Error>> {
    assert_tampered_fac1_is_rejected(&mut MemoryStore::new())
}

fn assert_opaque_command_decoder_boundaries(
    store: &mut SqliteStore,
    host: &ForkHostSigningKeyV1,
    adapter: &ForkAuthenticationAdapterSigningKeyV1,
    policy: &ForkAuthenticationPolicyV1,
    session: &pos_store::ForkAdmissionAuthoritySessionV1,
) -> Result<(), Box<dyn Error>> {
    let command = opaque_command(adapter, policy, vec![0xff])?;
    assert_eq!(
        ForkAdmissionHostCommandV1::from_canonical_cbor(&command),
        Err(ForkAdmissionCommandCodecErrorV1::InvalidEncoding)
    );

    let evidence = adapter.sign_authenticated_principal(AuthenticatedPrincipalRecordV1 {
        principal: PrincipalRefV1::try_new([4; 16], "test.local")?,
        adapter_id: "test-adapter".to_owned(),
        assurance: 1,
        issued_at: 0,
        expires_at: u64::MAX,
        registry_binding: Hash::from_bytes([3; 32]),
        operation_nonce: [5; 32],
    })?;
    let verified = verify_authenticated_principal_evidence_v1(policy, evidence)?;
    let principal = principal_digest_v1(&verified.evidence().record().principal)?;
    let fields = vec![
        Value::Text("POC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(
            store
                .fork_admission_host_record()?
                .store_id()
                .as_bytes()
                .to_vec(),
        ),
        Value::Bytes(session.identity().as_bytes().to_vec()),
        Value::Bytes(vec![119; 32]),
        Value::Bytes(verified.evidence().digest()?.as_bytes().to_vec()),
        Value::Bytes(principal.as_bytes().to_vec()),
        Value::Text("owner".to_owned()),
    ];
    for (index, value) in [
        (2, Value::Text("not-a-store".to_owned())),
        (3, Value::Text("not-an-identity".to_owned())),
        (4, Value::Text("not-an-operation".to_owned())),
        (5, Value::Text("not-an-evidence".to_owned())),
        (6, Value::Text("not-a-principal".to_owned())),
    ] {
        let mut malformed = fields.clone();
        malformed[index] = value;
        let command = opaque_command(adapter, policy, encode(&Value::Array(malformed))?)?;
        assert_eq!(
            ForkAdmissionHostCommandV1::from_canonical_cbor(&command),
            Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
        );
    }
    let command = principal_command(store, host, adapter, policy, session, [120; 32], 1, "owner")?;
    assert_eq!(
        store.execute_fork_admission_command(session, policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::Unauthenticated)
    );
    Ok(())
}

fn assert_opaque_recovery_decoder_boundaries(
    store: &mut SqliteStore,
    host: &ForkHostSigningKeyV1,
    session: &pos_store::ForkAdmissionAuthoritySessionV1,
) -> Result<(), Box<dyn Error>> {
    let recovery = opaque_recovery(&[0xff])?;
    assert_eq!(
        ForkAdmissionRecoveryProofV1::from_canonical_cbor(&recovery),
        Err(ForkAdmissionCommandCodecErrorV1::InvalidEncoding)
    );

    let host_record = store.fork_admission_host_record()?;
    let fields = vec![
        Value::Text("FRC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(host_record.store_id().as_bytes().to_vec()),
        Value::Bytes(session.identity().as_bytes().to_vec()),
        Value::Integer(1.into()),
        Value::Bytes(vec![118; 32]),
    ];
    for (index, value) in [
        (2, Value::Text("not-a-store".to_owned())),
        (3, Value::Text("not-an-identity".to_owned())),
        (4, Value::Text("not-a-kind".to_owned())),
        (5, Value::Text("not-an-operation".to_owned())),
    ] {
        let mut malformed = fields.clone();
        malformed[index] = value;
        let recovery = opaque_recovery(&encode(&Value::Array(malformed))?)?;
        assert_eq!(
            ForkAdmissionRecoveryProofV1::from_canonical_cbor(&recovery),
            Err(ForkAdmissionCommandCodecErrorV1::FieldOutOfBounds)
        );
    }
    for kind in [1_u8, 2] {
        let recovery = recovery_proof(store, host, session, kind, [118; 32])?;
        assert_eq!(
            store.recover_fork_admission_command(session, &recovery),
            Err(pos_core::ForkAdmissionErrorV1::OperationMissing)
        );
    }
    Ok(())
}

#[test]
fn sqlite_public_authority_rejects_opaque_decoder_payloads_and_checks_signed_paths(
) -> Result<(), Box<dyn Error>> {
    let host = ForkHostSigningKeyV1::from_seed([116; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([117; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open_in_memory()?;
    let session = open_session(&mut store, &host, &policy)?;
    assert_opaque_command_decoder_boundaries(&mut store, &host, &adapter, &policy, &session)?;
    assert_opaque_recovery_decoder_boundaries(&mut store, &host, &session)
}

#[test]
fn memory_rejects_fac1_and_frp1_before_authority_initialization() -> Result<(), Box<dyn Error>> {
    let host = ForkHostSigningKeyV1::from_seed([37; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([38; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut source = MemoryStore::new();
    let session = open_session(&mut source, &host, &policy)?;
    let command = principal_command(
        &source,
        &host,
        &adapter,
        &policy,
        &session,
        [39; 32],
        u64::MAX,
        "owner",
    )?;
    let proof = recovery_proof(&source, &host, &session, 1, [39; 32])?;
    let mut uninitialized = MemoryStore::new();
    assert_eq!(
        uninitialized.execute_fork_admission_command(&session, &policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::AuthorityUninitialized)
    );
    assert_eq!(
        uninitialized.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::AuthorityUninitialized)
    );
    Ok(())
}

#[test]
fn memory_rejects_stale_fac1_and_tampered_frp1_before_any_lookup() -> Result<(), Box<dyn Error>> {
    let host = ForkHostSigningKeyV1::from_seed([40; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([41; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = MemoryStore::new();
    let stale_session = open_session(&mut store, &host, &policy)?;
    let stale_command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &stale_session,
        [42; 32],
        u64::MAX,
        "owner",
    )?;
    let _current_session = reopen_session(&mut store, &host, &policy)?;
    assert_eq!(
        store.execute_fork_admission_command(&stale_session, &policy, &stale_command),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );

    let proof = recovery_proof(&store, &host, &stale_session, 1, [42; 32])?;
    let mut bytes = proof.to_canonical_cbor();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let tampered = ForkAdmissionRecoveryProofV1::from_canonical_cbor(&bytes)?;
    assert_eq!(
        store.recover_fork_admission_command(&stale_session, &tampered),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );
    Ok(())
}

#[test]
fn sqlite_rejects_a_tampered_fac1_without_persisting_an_operation() -> Result<(), Box<dyn Error>> {
    assert_tampered_fac1_is_rejected(&mut SqliteStore::open_in_memory()?)
}

#[test]
fn memory_rejects_a_second_owner_for_one_authenticated_principal() -> Result<(), Box<dyn Error>> {
    assert_principal_owner_binding_is_unique(&mut MemoryStore::new())
}

#[test]
fn sqlite_rejects_a_second_owner_for_one_authenticated_principal() -> Result<(), Box<dyn Error>> {
    assert_principal_owner_binding_is_unique(&mut SqliteStore::open_in_memory()?)
}

#[test]
fn memory_rejects_a_policy_other_than_its_pinned_policy() -> Result<(), Box<dyn Error>> {
    assert_pinned_policy_is_required(&mut MemoryStore::new())
}

#[test]
fn sqlite_rejects_a_policy_other_than_its_pinned_policy() -> Result<(), Box<dyn Error>> {
    assert_pinned_policy_is_required(&mut SqliteStore::open_in_memory()?)
}

#[test]
fn memory_rejects_a_fork_command_after_its_completed_fold_boundary() -> Result<(), Box<dyn Error>> {
    assert_stale_fold_boundary_is_rejected(&mut MemoryStore::new())
}

#[test]
fn sqlite_rejects_a_fork_command_after_its_completed_fold_boundary() -> Result<(), Box<dyn Error>> {
    assert_stale_fold_boundary_is_rejected(&mut SqliteStore::open_in_memory()?)
}

#[test]
fn sqlite_frp1_rejects_missing_and_malformed_operation_rows() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-operation-row.db");
    let path = path.to_string_lossy().into_owned();
    let operation_id = [113; 32];
    let (mut store, host, session) = sqlite_principal_recovery_fixture(&path, operation_id)?;
    let proof = recovery_proof(&store, &host, &session, 1, operation_id)?;
    let connection = Connection::open(&path)?;
    let row = connection.query_row(
        "SELECT evidence_digest, commitment, result_digest, child_id
         FROM fork_admission_operations WHERE kind = 1 AND operation_id = ?1",
        params![operation_id.to_vec()],
        |record| {
            Ok((
                record.get::<_, Vec<u8>>(0)?,
                record.get::<_, Vec<u8>>(1)?,
                record.get::<_, Vec<u8>>(2)?,
                record.get::<_, Option<String>>(3)?,
            ))
        },
    )?;
    connection.execute(
        "DELETE FROM fork_admission_operations WHERE kind = 1 AND operation_id = ?1",
        params![operation_id.to_vec()],
    )?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::OperationMissing)
    );
    connection.execute(
        "INSERT INTO fork_admission_operations
         (kind, operation_id, evidence_digest, commitment, result_digest, child_id)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![operation_id.to_vec(), row.0, row.1, row.2, row.3],
    )?;
    connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    connection.execute(
        "UPDATE fork_admission_operations SET evidence_digest = ?1
         WHERE kind = 1 AND operation_id = ?2",
        params![vec![0_u8; 31], operation_id.to_vec()],
    )?;
    drop(connection);
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_frp1_rejects_an_operation_row_with_an_invalid_child_id() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-invalid-child.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([121; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([122; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(&path)?;
    bind_open_gate(&mut store)?;
    let session = open_session(&mut store, &host, &policy)?;
    let principal = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        [123; 32],
        u64::MAX,
        "owner",
    )?;
    store.execute_fork_admission_command(&session, &policy, &principal)?;
    let parent = store.create_timeline("invalid-operation-child-parent")?;
    let operation_id = [124; 32];
    let command = fork_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        operation_id,
        parent.id(),
        "invalid-operation-child",
    )?;
    assert!(matches!(
        store.execute_fork_admission_command(&session, &policy, &command)?,
        ForkAdmissionOperationResultV1::Fork(_)
    ));
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_operations SET child_id = 'not-a-timeline'
         WHERE kind = 2 AND operation_id = ?1",
        params![operation_id.to_vec()],
    )?;
    drop(connection);
    let proof = recovery_proof(&store, &host, &session, 2, operation_id)?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_frp1_maps_a_recovery_transaction_lock_to_storage_indeterminate(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-recovery-lock.db");
    let path = path.to_string_lossy().into_owned();
    let operation_id = [131; 32];
    let (mut store, host, session) = sqlite_principal_recovery_fixture(&path, operation_id)?;
    let proof = recovery_proof(&store, &host, &session, 1, operation_id)?;
    let lock = Connection::open(&path)?;
    lock.execute_batch("BEGIN EXCLUSIVE")?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::StorageIndeterminate)
    );
    lock.execute_batch("ROLLBACK")?;
    Ok(())
}

#[test]
fn sqlite_frp1_recovers_pob1_after_restart_and_rejects_corruption() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-recovery.db");
    let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
    let policy = authority_policy(&adapter)?;
    {
        let mut store = SqliteStore::open(&path.to_string_lossy())?;
        let session = open_session(&mut store, &host, &policy)?;
        let command = principal_command(
            &store,
            &host,
            &adapter,
            &policy,
            &session,
            [43; 32],
            u64::MAX,
            "owner",
        )?;
        assert!(matches!(
            store.execute_fork_admission_command(&session, &policy, &command)?,
            ForkAdmissionOperationResultV1::PrincipalOwner(_)
        ));
    }
    {
        let mut store = SqliteStore::open(&path.to_string_lossy())?;
        let session = reopen_session(&mut store, &host, &policy)?;
        let proof = recovery_proof(&store, &host, &session, 1, [43; 32])?;
        assert!(matches!(
            store.recover_fork_admission_command(&session, &proof)?,
            ForkAdmissionOperationResultV1::PrincipalOwner(_)
        ));
    }
    let connection = rusqlite::Connection::open(&path)?;
    let pob1_cbor = connection.query_row(
        "SELECT pob1_cbor FROM fork_principal_owner_bindings WHERE operation_id = ?1",
        params![vec![43_u8; 32]],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    connection.execute(
        "UPDATE fork_principal_owner_bindings SET pob1_cbor = ?1 WHERE operation_id = ?2",
        params![vec![0xff_u8], vec![43_u8; 32]],
    )?;
    drop(connection);
    let mut store = SqliteStore::open(&path.to_string_lossy())?;
    let session = reopen_session(&mut store, &host, &policy)?;
    let proof = recovery_proof(&store, &host, &session, 1, [43; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    drop(store);

    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_principal_owner_bindings SET principal_digest = ?1, pob1_cbor = ?2 WHERE operation_id = ?3",
        params![vec![0_u8; 32], pob1_cbor, vec![43_u8; 32]],
    )?;
    drop(connection);
    let mut store = SqliteStore::open(&path.to_string_lossy())?;
    let session = reopen_session(&mut store, &host, &policy)?;
    let proof = recovery_proof(&store, &host, &session, 1, [43; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_frp1_rejects_missing_or_uncommitted_pob1_results() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-pob1-result.db");
    let path = path.to_string_lossy().into_owned();
    let operation_id = [45; 32];
    let (mut store, host, session) = sqlite_principal_recovery_fixture(&path, operation_id)?;
    let proof = recovery_proof(&store, &host, &session, 1, operation_id)?;
    let connection = Connection::open(&path)?;
    let binding = connection.query_row(
        "SELECT principal_digest, pob1_cbor FROM fork_principal_owner_bindings WHERE operation_id = ?1",
        params![operation_id.to_vec()],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    let result_digest = connection.query_row(
        "SELECT result_digest FROM fork_admission_operations WHERE kind = 1 AND operation_id = ?1",
        params![operation_id.to_vec()],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    connection.execute(
        "DELETE FROM fork_principal_owner_bindings WHERE operation_id = ?1",
        params![operation_id.to_vec()],
    )?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    connection.execute(
        "INSERT INTO fork_principal_owner_bindings (operation_id, principal_digest, pob1_cbor)
         VALUES (?1, ?2, ?3)",
        params![operation_id.to_vec(), binding.0, binding.1],
    )?;
    connection.execute(
        "UPDATE fork_admission_operations SET result_digest = ?1
         WHERE kind = 1 AND operation_id = ?2",
        params![vec![0_u8; 32], operation_id.to_vec()],
    )?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    connection.execute(
        "UPDATE fork_admission_operations SET result_digest = ?1, commitment = ?2
         WHERE kind = 1 AND operation_id = ?3",
        params![result_digest, vec![0_u8; 32], operation_id.to_vec()],
    )?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_frp1_rejects_an_incoherent_principal_operation_row() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory
        .path()
        .join("fork-admission-principal-row-shape.db");
    let path = path.to_string_lossy().into_owned();
    let operation_id = [46; 32];
    let (mut store, host, session) = sqlite_principal_recovery_fixture(&path, operation_id)?;
    let proof = recovery_proof(&store, &host, &session, 1, operation_id)?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_operations SET child_id = ?1
         WHERE kind = 1 AND operation_id = ?2",
        params![TimelineId::new().to_string(), operation_id.to_vec()],
    )?;
    drop(connection);

    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_frp1_maps_result_table_faults_to_storage_indeterminate() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-pob1-table-fault.db");
    let path = path.to_string_lossy().into_owned();
    let operation_id = [47; 32];
    let (mut store, host, session) = sqlite_principal_recovery_fixture(&path, operation_id)?;
    let proof = recovery_proof(&store, &host, &session, 1, operation_id)?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("DROP TABLE fork_principal_owner_bindings;")?;
    drop(connection);
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::StorageIndeterminate)
    );
    drop(store);

    for (name, fault) in [
        ("far1", "DROP TABLE fork_admissions;"),
        ("pob1", "DROP TABLE fork_principal_owner_bindings;"),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join(format!("fork-admission-{name}-result.db"));
        let path = path.to_string_lossy().into_owned();
        let (mut store, host, _, session, _) =
            sqlite_fork_recovery_fixture(&path, "result-parent", "result-child")?;
        let proof = recovery_proof(&store, &host, &session, 2, [54; 32])?;
        let connection = Connection::open(&path)?;
        connection.execute_batch(fault)?;
        drop(connection);
        assert_eq!(
            store.recover_fork_admission_command(&session, &proof),
            Err(pos_core::ForkAdmissionErrorV1::StorageIndeterminate),
            "{name}"
        );
        drop(store);
    }
    Ok(())
}

#[test]
fn sqlite_frp1_rejects_far1_when_the_child_graph_is_corrupt() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-far1.db");
    let path = path.to_string_lossy().into_owned();
    let (store, host, policy, _, child_id) =
        sqlite_fork_recovery_fixture(&path, "far1-parent", "far1-child")?;
    drop(store);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "UPDATE timelines SET fork_seq = 1 WHERE id = ?1",
        params![child_id.to_string()],
    )?;
    drop(connection);
    let mut store = SqliteStore::open(&path)?;
    let session = reopen_session(&mut store, &host, &policy)?;
    let proof = recovery_proof(&store, &host, &session, 2, [54; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_frp1_rejects_missing_or_malformed_far1() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-far1-bytes.db");
    let path = path.to_string_lossy().into_owned();
    let (mut store, host, _policy, session, child_id) =
        sqlite_fork_recovery_fixture(&path, "far1-bytes-parent", "far1-bytes-child")?;
    let proof = recovery_proof(&store, &host, &session, 2, [54; 32])?;
    let connection = Connection::open(&path)?;
    let far1_cbor = connection.query_row(
        "SELECT far1_cbor FROM fork_admissions WHERE child_id = ?1",
        params![child_id.to_string()],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    connection.execute(
        "DELETE FROM fork_admissions WHERE child_id = ?1",
        params![child_id.to_string()],
    )?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    connection.execute(
        "INSERT INTO fork_admissions (child_id, far1_cbor) VALUES (?1, ?2)",
        params![child_id.to_string(), far1_cbor],
    )?;
    connection.execute(
        "UPDATE fork_admissions SET far1_cbor = ?1 WHERE child_id = ?2",
        params![vec![0xff_u8], child_id.to_string()],
    )?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_frp1_rejects_tampered_fork_commitment_child_name_and_pob1_edge(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-commitment.db");
    let host = ForkHostSigningKeyV1::from_seed([81; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([82; 32])?;
    let policy = authority_policy(&adapter)?;
    let child_id;
    {
        let mut store = SqliteStore::open(&path.to_string_lossy())?;
        bind_open_gate(&mut store)?;
        let session = open_session(&mut store, &host, &policy)?;
        let principal = principal_command(
            &store,
            &host,
            &adapter,
            &policy,
            &session,
            [83; 32],
            u64::MAX,
            "owner",
        )?;
        store.execute_fork_admission_command(&session, &policy, &principal)?;
        let parent = store.create_timeline("commitment-parent")?;
        let command = fork_command(
            &store,
            &host,
            &adapter,
            &policy,
            &session,
            [84; 32],
            parent.id(),
            "commitment-child",
        )?;
        let ForkAdmissionOperationResultV1::Fork(receipt) =
            store.execute_fork_admission_command(&session, &policy, &command)?
        else {
            return Err("FCC1 did not return a FAR1 receipt".into());
        };
        child_id = receipt.child_id;
    }

    let connection = rusqlite::Connection::open(&path)?;
    let commitment = connection.query_row(
        "SELECT commitment FROM fork_admission_operations WHERE kind = 2 AND operation_id = ?1",
        params![vec![84_u8; 32]],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    connection.execute(
        "UPDATE fork_admission_operations SET commitment = ?1 WHERE kind = 2 AND operation_id = ?2",
        params![vec![0_u8; 32], vec![84_u8; 32]],
    )?;
    drop(connection);
    let mut store = SqliteStore::open(&path.to_string_lossy())?;
    let session = reopen_session(&mut store, &host, &policy)?;
    let proof = recovery_proof(&store, &host, &session, 2, [84; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    drop(store);

    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_operations SET commitment = ?1 WHERE kind = 2 AND operation_id = ?2",
        params![commitment, vec![84_u8; 32]],
    )?;
    connection.execute(
        "UPDATE timelines SET name = 'tampered-child' WHERE id = ?1",
        params![child_id.to_string()],
    )?;
    drop(connection);
    let mut store = SqliteStore::open(&path.to_string_lossy())?;
    let session = reopen_session(&mut store, &host, &policy)?;
    let proof = recovery_proof(&store, &host, &session, 2, [84; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    drop(store);

    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "UPDATE timelines SET name = 'commitment-child' WHERE id = ?1",
        params![child_id.to_string()],
    )?;
    connection.execute(
        "UPDATE fork_principal_owner_bindings SET principal_digest = ?1 WHERE operation_id = ?2",
        params![vec![0_u8; 32], vec![83_u8; 32]],
    )?;
    drop(connection);
    let mut store = SqliteStore::open(&path.to_string_lossy())?;
    let session = reopen_session(&mut store, &host, &policy)?;
    let proof = recovery_proof(&store, &host, &session, 2, [84; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_file_backed_recovery_serializes_with_a_concurrent_fork_commit(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory
        .path()
        .join("concurrent-fork-admission-recovery.db");
    let host = ForkHostSigningKeyV1::from_seed([91; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([92; 32])?;
    let policy = authority_policy(&adapter)?;
    {
        let mut store = SqliteStore::open(&path.to_string_lossy())?;
        let session = open_session(&mut store, &host, &policy)?;
        let principal = principal_command(
            &store,
            &host,
            &adapter,
            &policy,
            &session,
            [93; 32],
            u64::MAX,
            "owner",
        )?;
        store.execute_fork_admission_command(&session, &policy, &principal)?;
    }

    let mut recovery_store = SqliteStore::open(&path.to_string_lossy())?;
    let recovery_session = reopen_session(&mut recovery_store, &host, &policy)?;
    let recovery = recovery_proof(&recovery_store, &host, &recovery_session, 1, [93; 32])?;
    let mut writer_store = SqliteStore::open(&path.to_string_lossy())?;
    bind_open_gate(&mut writer_store)?;
    let writer_session = reopen_session(&mut writer_store, &host, &policy)?;
    let parent = writer_store.create_timeline("concurrent-recovery-fork-parent")?;
    let command = fork_command(
        &writer_store,
        &host,
        &adapter,
        &policy,
        &writer_session,
        [94; 32],
        parent.id(),
        "concurrent-recovery-child",
    )?;

    let barrier = Arc::new(Barrier::new(2));
    let recovery_barrier = Arc::clone(&barrier);
    let recovery_thread = std::thread::spawn(move || {
        recovery_barrier.wait();
        recovery_store.recover_fork_admission_command(&recovery_session, &recovery)
    });
    let writer_thread = std::thread::spawn(move || {
        barrier.wait();
        writer_store.execute_fork_admission_command(&writer_session, &policy, &command)
    });
    assert!(matches!(
        recovery_thread
            .join()
            .map_err(|_| std::io::Error::other("recovery thread panicked"))??,
        ForkAdmissionOperationResultV1::PrincipalOwner(_)
    ));
    assert!(matches!(
        writer_thread
            .join()
            .map_err(|_| std::io::Error::other("writer thread panicked"))??,
        ForkAdmissionOperationResultV1::Fork(_)
    ));
    Ok(())
}

#[test]
fn sqlite_frp1_maps_principal_result_column_type_faults_to_storage_indeterminate(
) -> Result<(), Box<dyn Error>> {
    for (name, column) in [
        ("principal-digest", "principal_digest"),
        ("pob1", "pob1_cbor"),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join(format!("fork-admission-{name}-type.db"));
        let path = path.to_string_lossy().into_owned();
        let operation_id = [151; 32];
        let (mut store, host, session) = sqlite_principal_recovery_fixture(&path, operation_id)?;
        let proof = recovery_proof(&store, &host, &session, 1, operation_id)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
        connection.execute(
            &format!(
                "UPDATE fork_principal_owner_bindings SET {column} = 'wrong SQLite type' \
                 WHERE operation_id = ?1"
            ),
            params![operation_id.to_vec()],
        )?;
        drop(connection);
        assert_eq!(
            store.recover_fork_admission_command(&session, &proof),
            Err(pos_core::ForkAdmissionErrorV1::StorageIndeterminate),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn sqlite_frp1_rejects_a_mismatched_fork_result_row() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory
        .path()
        .join("fork-admission-mismatched-fork-result.db");
    let path = path.to_string_lossy().into_owned();
    let (mut store, host, _, session, _) =
        sqlite_fork_recovery_fixture(&path, "mismatch-parent", "mismatch-child")?;
    let proof = recovery_proof(&store, &host, &session, 2, [54; 32])?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_operations SET result_digest = ?1 \
         WHERE kind = 2 AND operation_id = ?2",
        params![vec![0_u8; 32], vec![54_u8; 32]],
    )?;
    drop(connection);
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_frp1_rejects_a_fork_result_without_its_child_timeline() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory
        .path()
        .join("fork-admission-missing-fork-child.db");
    let path = path.to_string_lossy().into_owned();
    let (mut store, host, _, session, child_id) =
        sqlite_fork_recovery_fixture(&path, "missing-child-parent", "missing-child")?;
    let proof = recovery_proof(&store, &host, &session, 2, [54; 32])?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("PRAGMA foreign_keys = OFF")?;
    connection.execute(
        "DELETE FROM timelines WHERE id = ?1",
        params![child_id.to_string()],
    )?;
    drop(connection);
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_frp1_rejects_a_fork_result_with_a_missing_parent_timeline() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-missing-parent.db");
    let path = path.to_string_lossy().into_owned();
    let (mut store, host, _, session, child_id) =
        sqlite_fork_recovery_fixture(&path, "missing-parent", "orphan-child")?;
    let proof = recovery_proof(&store, &host, &session, 2, [54; 32])?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("PRAGMA foreign_keys = OFF")?;
    let parent_id: String = connection.query_row(
        "SELECT parent_id FROM timelines WHERE id = ?1",
        params![child_id.to_string()],
        |row| row.get(0),
    )?;
    connection.execute("DELETE FROM timelines WHERE id = ?1", params![parent_id])?;
    drop(connection);
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_frp1_rejects_fork_binding_hashes_with_wrong_lengths() -> Result<(), Box<dyn Error>> {
    for (name, column) in [
        ("operation-id", "operation_id"),
        ("principal-digest", "principal_digest"),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join(format!("fork-admission-{name}-length.db"));
        let path = path.to_string_lossy().into_owned();
        let (mut store, host, _, session, _) =
            sqlite_fork_recovery_fixture(&path, "bad-hash-parent", "bad-hash-child")?;
        let proof = recovery_proof(&store, &host, &session, 2, [54; 32])?;
        let connection = Connection::open(&path)?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
        connection.execute(
            &format!(
                "UPDATE fork_principal_owner_bindings SET {column} = ?1 \
                 WHERE operation_id = ?2"
            ),
            params![vec![0_u8; 31], vec![53_u8; 32]],
        )?;
        drop(connection);
        assert_eq!(
            store.recover_fork_admission_command(&session, &proof),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn sqlite_fac1_rejects_host_signed_evidence_outside_the_configured_policy(
) -> Result<(), Box<dyn Error>> {
    let host = ForkHostSigningKeyV1::from_seed([161; 32])?;
    let accepted_adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([162; 32])?;
    let accepted_policy = authority_policy(&accepted_adapter)?;
    let rejected_adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([163; 32])?;
    let rejected_policy = authority_policy(&rejected_adapter)?;
    let mut store = SqliteStore::open_in_memory()?;
    let session = open_session(&mut store, &host, &accepted_policy)?;
    let command = principal_command(
        &store,
        &host,
        &rejected_adapter,
        &rejected_policy,
        &session,
        [164; 32],
        u64::MAX,
        "owner",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &accepted_policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::Unauthenticated)
    );
    Ok(())
}

#[test]
fn sqlite_fac1_fails_closed_on_corrupt_principal_owner_lookup_rows() -> Result<(), Box<dyn Error>> {
    for (name, update, expected) in [
        (
            "operation-id-type",
            "operation_id = 'wrong SQLite type'",
            pos_core::ForkAdmissionErrorV1::StorageIndeterminate,
        ),
        (
            "pob1-type",
            "pob1_cbor = 'wrong SQLite type'",
            pos_core::ForkAdmissionErrorV1::StorageIndeterminate,
        ),
        (
            "principal-missing",
            "principal_digest = X'0000000000000000000000000000000000000000000000000000000000000000'",
            pos_core::ForkAdmissionErrorV1::InvalidRequest,
        ),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join(format!("fork-admission-{name}.db"));
        let host = ForkHostSigningKeyV1::from_seed([171; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([172; 32])?;
        let policy = authority_policy(&adapter)?;
        let mut store = SqliteStore::open(&path.to_string_lossy())?;
        let session = open_session(&mut store, &host, &policy)?;
        let principal = principal_command(
            &store,
            &host,
            &adapter,
            &policy,
            &session,
            [173; 32],
            u64::MAX,
            "owner",
        )?;
        store.execute_fork_admission_command(&session, &policy, &principal)?;
        let connection = Connection::open(&path)?;
        connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
        connection.execute(
            &format!(
                "UPDATE fork_principal_owner_bindings SET {update} WHERE operation_id = ?1"
            ),
            params![vec![173_u8; 32]],
        )?;
        drop(connection);
        let parent = store.create_timeline("corrupt-principal-lookup-parent")?;
        let command = fork_command(
            &store,
            &host,
            &adapter,
            &policy,
            &session,
            [174; 32],
            parent.id(),
            "corrupt-principal-lookup-child",
        )?;
        assert_eq!(
            store.execute_fork_admission_command(&session, &policy, &command),
            Err(expected),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn public_bootstrap_errors_keep_their_closed_admission_meaning() {
    for (bootstrap, admission) in [
        (
            ForkAdmissionAuthorityErrorV1::AuthorityUninitialized,
            pos_core::ForkAdmissionErrorV1::AuthorityUninitialized,
        ),
        (
            ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized,
            pos_core::ForkAdmissionErrorV1::AuthorityAlreadyInitialized,
        ),
        (
            ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch,
            pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch,
        ),
        (
            ForkAdmissionAuthorityErrorV1::EntropyUnavailable,
            pos_core::ForkAdmissionErrorV1::EntropyUnavailable,
        ),
        (
            ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable,
            pos_core::ForkAdmissionErrorV1::AuthorityClockUnavailable,
        ),
        (
            ForkAdmissionAuthorityErrorV1::ClockRollback,
            pos_core::ForkAdmissionErrorV1::ClockRollback,
        ),
        (
            ForkAdmissionAuthorityErrorV1::CorruptAuthority,
            pos_core::ForkAdmissionErrorV1::CorruptAuthority,
        ),
        (
            ForkAdmissionAuthorityErrorV1::StorageIndeterminate,
            pos_core::ForkAdmissionErrorV1::StorageIndeterminate,
        ),
    ] {
        let mapped = pos_core::ForkAdmissionErrorV1::from(bootstrap);
        assert_eq!(mapped, admission);
        assert!(!mapped.to_string().is_empty());
    }
}

/// A superseded session cannot retry an exact FAC1 or recover through FRP1,
/// even for a committed operation, and it learns nothing about absent rows.
fn assert_superseded_session_cannot_retry_or_recover<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([161; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([162; 32])?;
    let policy = authority_policy(&adapter)?;
    let stale = open_session(store, &host, &policy)?;
    let command = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &stale,
        [163; 32],
        u64::MAX,
        "owner",
    )?;
    let committed = store.execute_fork_admission_command(&stale, &policy, &command)?;
    let stale_recovery = recovery_proof(store, &host, &stale, 1, [163; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&stale, &stale_recovery)?,
        committed
    );
    let stale_absent = recovery_proof(store, &host, &stale, 1, [164; 32])?;

    let current = reopen_session(store, &host, &policy)?;
    assert_eq!(
        store.execute_fork_admission_command(&stale, &policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );
    assert_eq!(
        store.recover_fork_admission_command(&stale, &stale_recovery),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );
    assert_eq!(
        store.recover_fork_admission_command(&stale, &stale_absent),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );

    let current_recovery = recovery_proof(store, &host, &current, 1, [163; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&current, &current_recovery)?,
        committed
    );
    Ok(())
}

#[test]
fn memory_superseded_session_cannot_retry_or_recover() -> Result<(), Box<dyn Error>> {
    assert_superseded_session_cannot_retry_or_recover(&mut MemoryStore::new())
}

#[test]
fn sqlite_superseded_session_cannot_retry_or_recover() -> Result<(), Box<dyn Error>> {
    assert_superseded_session_cannot_retry_or_recover(&mut SqliteStore::open_in_memory()?)
}

#[test]
fn sqlite_session_from_another_adapter_instance_cannot_retry_or_recover(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-foreign-session.db");
    let path = path.to_string_lossy().into_owned();
    let (mut first, host, first_session) = sqlite_principal_recovery_fixture(&path, [171; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([112; 32])?;
    let policy = authority_policy(&adapter)?;
    let command = principal_command(
        &first,
        &host,
        &adapter,
        &policy,
        &first_session,
        [171; 32],
        u64::MAX,
        "owner",
    )?;
    let recovery = recovery_proof(&first, &host, &first_session, 1, [171; 32])?;
    let committed = first.recover_fork_admission_command(&first_session, &recovery)?;

    let mut second = SqliteStore::open(&path)?;
    let second_session = reopen_session(&mut second, &host, &policy)?;
    assert_eq!(
        second.execute_fork_admission_command(&first_session, &policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );
    assert_eq!(
        second.recover_fork_admission_command(&first_session, &recovery),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );
    let second_recovery = recovery_proof(&second, &host, &second_session, 1, [171; 32])?;
    assert_eq!(
        second.recover_fork_admission_command(&second_session, &second_recovery)?,
        committed
    );
    assert_eq!(
        first.execute_fork_admission_command(&first_session, &policy, &command)?,
        committed
    );
    Ok(())
}

#[test]
fn sqlite_unequal_fac1_reuse_reports_committed_corruption_before_conflict(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory
        .path()
        .join("fork-admission-corruption-before-conflict.db");
    let path = path.to_string_lossy().into_owned();
    let (mut store, host, session) = sqlite_principal_recovery_fixture(&path, [181; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([112; 32])?;
    let policy = authority_policy(&adapter)?;
    let unequal = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        [181; 32],
        u64::MAX,
        "other-owner",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &unequal),
        Err(pos_core::ForkAdmissionErrorV1::Conflict)
    );
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_principal_owner_bindings SET pob1_cbor = ?1 WHERE operation_id = ?2",
        params![vec![0xff_u8], vec![181_u8; 32]],
    )?;
    drop(connection);
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &unequal),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

fn wall_micros() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros(),
    )?)
}

fn assert_equal_owner_reuses_the_committed_binding<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([181; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([182; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let first = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [183; 32],
        u64::MAX,
        "owner",
    )?;
    let committed = store.execute_fork_admission_command(&session, &policy, &first)?;
    let second = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [184; 32],
        u64::MAX,
        "owner",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &second)?,
        committed
    );
    let recovery = recovery_proof(store, &host, &session, 1, [184; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &recovery),
        Err(pos_core::ForkAdmissionErrorV1::OperationMissing)
    );
    Ok(())
}

#[test]
fn memory_equal_owner_under_a_new_operation_reuses_the_committed_binding(
) -> Result<(), Box<dyn Error>> {
    assert_equal_owner_reuses_the_committed_binding(&mut MemoryStore::new())
}

#[test]
fn sqlite_equal_owner_under_a_new_operation_reuses_the_committed_binding(
) -> Result<(), Box<dyn Error>> {
    assert_equal_owner_reuses_the_committed_binding(&mut SqliteStore::open_in_memory()?)
}

fn assert_fork_without_a_binding_is_invalid<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1 + EventStore,
{
    let host = ForkHostSigningKeyV1::from_seed([185; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([186; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let parent = store.create_timeline("unbound-parent")?;
    let command = fork_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [187; 32],
        parent.id(),
        "unbound-child",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::InvalidRequest)
    );
    let recovery = recovery_proof(store, &host, &session, 2, [187; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &recovery),
        Err(pos_core::ForkAdmissionErrorV1::OperationMissing)
    );
    Ok(())
}

#[test]
fn memory_fork_without_a_principal_owner_binding_is_an_invalid_request(
) -> Result<(), Box<dyn Error>> {
    assert_fork_without_a_binding_is_invalid(&mut MemoryStore::new())
}

#[test]
fn sqlite_fork_without_a_principal_owner_binding_is_an_invalid_request(
) -> Result<(), Box<dyn Error>> {
    assert_fork_without_a_binding_is_invalid(&mut SqliteStore::open_in_memory()?)
}

fn assert_committed_retry_survives_expiry<S>(store: &mut S) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([191; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([192; 32])?;
    let policy = authority_policy(&adapter)?;
    let session = open_session(store, &host, &policy)?;
    let expires_at = wall_micros()? + 2_000_000;
    let command = principal_command(
        store, &host, &adapter, &policy, &session, [193; 32], expires_at, "owner",
    )?;
    let committed = store.execute_fork_admission_command(&session, &policy, &command)?;
    while wall_micros()? <= expires_at {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &command)?,
        committed
    );
    let unequal = principal_command(
        store,
        &host,
        &adapter,
        &policy,
        &session,
        [193; 32],
        1,
        "other-owner",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &unequal),
        Err(pos_core::ForkAdmissionErrorV1::Conflict)
    );
    let recovery = recovery_proof(store, &host, &session, 1, [193; 32])?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &recovery)?,
        committed
    );
    Ok(())
}

#[test]
fn memory_exact_committed_retry_survives_expiry_and_unequal_reuse_conflicts(
) -> Result<(), Box<dyn Error>> {
    assert_committed_retry_survives_expiry(&mut MemoryStore::new())
}

#[test]
fn sqlite_exact_committed_retry_survives_expiry_and_unequal_reuse_conflicts(
) -> Result<(), Box<dyn Error>> {
    assert_committed_retry_survives_expiry(&mut SqliteStore::open_in_memory()?)
}

fn assert_commands_copied_to_another_store_are_rejected<S>(
    first: &mut S,
    second: &mut S,
) -> Result<(), Box<dyn Error>>
where
    S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1,
{
    let host = ForkHostSigningKeyV1::from_seed([201; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([202; 32])?;
    let policy = authority_policy(&adapter)?;
    let first_session = open_session(first, &host, &policy)?;
    let second_session = open_session(second, &host, &policy)?;
    let command = principal_command(
        first,
        &host,
        &adapter,
        &policy,
        &first_session,
        [203; 32],
        u64::MAX,
        "owner",
    )?;
    first.execute_fork_admission_command(&first_session, &policy, &command)?;
    let proof = recovery_proof(first, &host, &first_session, 1, [203; 32])?;
    assert_eq!(
        second.execute_fork_admission_command(&second_session, &policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );
    assert_eq!(
        second.recover_fork_admission_command(&second_session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch)
    );
    let local = recovery_proof(second, &host, &second_session, 1, [203; 32])?;
    assert_eq!(
        second.recover_fork_admission_command(&second_session, &local),
        Err(pos_core::ForkAdmissionErrorV1::OperationMissing)
    );
    Ok(())
}

#[test]
fn memory_fac1_and_frp1_copied_to_another_store_write_nothing() -> Result<(), Box<dyn Error>> {
    assert_commands_copied_to_another_store_are_rejected(
        &mut MemoryStore::new(),
        &mut MemoryStore::new(),
    )
}

#[test]
fn sqlite_fac1_and_frp1_copied_to_another_store_write_nothing() -> Result<(), Box<dyn Error>> {
    assert_commands_copied_to_another_store_are_rejected(
        &mut SqliteStore::open_in_memory()?,
        &mut SqliteStore::open_in_memory()?,
    )
}

#[test]
fn sqlite_fac1_rejects_clock_rollback_without_writes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-fac1-rollback.db");
    let path = path.to_string_lossy().into_owned();
    let host = ForkHostSigningKeyV1::from_seed([211; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([212; 32])?;
    let policy = authority_policy(&adapter)?;
    let mut store = SqliteStore::open(&path)?;
    let session = open_session(&mut store, &host, &policy)?;
    Connection::open(&path)?.execute(
        "UPDATE fork_admission_authority SET last_authority_wall_time = ?1 WHERE singleton = 1",
        [i64::MAX],
    )?;
    let command = principal_command(
        &store,
        &host,
        &adapter,
        &policy,
        &session,
        [213; 32],
        u64::MAX,
        "owner",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &command),
        Err(pos_core::ForkAdmissionErrorV1::ClockRollback)
    );
    let connection = Connection::open(&path)?;
    let count = |table: &str| -> rusqlite::Result<i64> {
        connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
    };
    assert_eq!(count("fork_admission_operations")?, 0);
    assert_eq!(count("fork_principal_owner_bindings")?, 0);
    assert_eq!(
        connection.query_row(
            "SELECT last_authority_wall_time FROM fork_admission_authority",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        i64::MAX
    );
    Ok(())
}

#[test]
fn sqlite_corrupt_committed_graph_precedes_expired_authentication() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-corrupt-expired.db");
    let path = path.to_string_lossy().into_owned();
    let (mut store, host, session) = sqlite_principal_recovery_fixture(&path, [214; 32])?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([112; 32])?;
    let policy = authority_policy(&adapter)?;
    Connection::open(&path)?.execute(
        "UPDATE fork_admission_operations SET commitment = ?1
         WHERE kind = 1 AND operation_id = ?2",
        params![vec![0_u8; 32], vec![214_u8; 32]],
    )?;
    let expired = principal_command(
        &store, &host, &adapter, &policy, &session, [214; 32], 1, "owner",
    )?;
    assert_eq!(
        store.execute_fork_admission_command(&session, &policy, &expired),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_frp1_rejects_a_fork_whose_principal_owner_binding_is_orphaned(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-orphaned-pob1.db");
    let path = path.to_string_lossy().into_owned();
    let (mut store, host, _, session, _) =
        sqlite_fork_recovery_fixture(&path, "orphan-pob1-parent", "orphan-pob1-child")?;
    let proof = recovery_proof(&store, &host, &session, 2, [54; 32])?;
    Connection::open(&path)?.execute(
        "DELETE FROM fork_admission_operations WHERE kind = 1 AND operation_id = ?1",
        params![vec![53_u8; 32]],
    )?;
    assert_eq!(
        store.recover_fork_admission_command(&session, &proof),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    Ok(())
}

fn open_policy_session<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &mut S,
    signer: &ForkHostSigningKeyV1,
) -> Result<ForkAdmissionAuthoritySessionV1, Box<dyn Error>> {
    let host_key = PublicKey::from_bytes(signer.public_key());
    let open = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_open(&open.canonical_bytes())?;
    Ok(store.finalize_fork_admission_open(&open, &signature)?)
}

fn stored_fah1(path: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    Ok(Connection::open(path)?.query_row(
        "SELECT fah1_cbor FROM fork_admission_authority WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?)
}

fn bootstrapped_sqlite(
    directory: &tempfile::TempDir,
    signer: &ForkHostSigningKeyV1,
) -> Result<(SqliteStore, String), Box<dyn Error>> {
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    bootstrap(&mut store, signer)?;
    Ok((store, path))
}

#[test]
fn sqlite_malformed_column_types_are_corrupt_authority() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    for update in [
        "UPDATE fork_admission_authority SET fah1_cbor = 'text' WHERE singleton = 1",
        "UPDATE fork_admission_authority SET fah1_cbor = 1 WHERE singleton = 1",
        "UPDATE fork_admission_authority SET last_authority_wall_time = 1.5 WHERE singleton = 1",
        "UPDATE fork_admission_authority SET last_authority_wall_time = X'01' WHERE singleton = 1",
    ] {
        let directory = tempfile::tempdir()?;
        let (store, path) = bootstrapped_sqlite(&directory, &signer)?;
        Connection::open(&path)?.execute(update, [])?;
        assert_eq!(
            store.fork_admission_host_record(),
            Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority),
            "{update}"
        );
    }
    Ok(())
}

#[test]
fn sqlite_null_fah1_row_is_corrupt_and_never_overwritten() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    let challenge = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_initialize(&challenge.canonical_bytes())?;
    Connection::open(&path)?.execute(
        "INSERT INTO fork_admission_authority (singleton, fah1_cbor, last_authority_wall_time) \
         VALUES (1, NULL, 0)",
        [],
    )?;
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    assert_eq!(
        store.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    assert_eq!(
        store.begin_fork_admission_initialize(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    assert_eq!(stored_fah1(&path)?, None);
    Ok(())
}

#[test]
fn sqlite_fence_advance_never_rewrites_fah1() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let directory = tempfile::tempdir()?;
    let (mut store, path) = bootstrapped_sqlite(&directory, &signer)?;
    let fah1 = store.fork_admission_host_record()?.canonical_bytes();
    let session = open_policy_session(&mut store, &signer)?;
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TRIGGER immutable_fah1
         BEFORE UPDATE OF fah1_cbor ON fork_admission_authority
         BEGIN SELECT RAISE(ABORT, 'FAH1 is immutable'); END;",
    )?;
    store.advance_fork_admission_wall_fence(&session)?;
    assert_eq!(stored_fah1(&path)?, Some(fah1));

    connection.execute_batch(
        "CREATE TRIGGER reject_fence
         BEFORE UPDATE ON fork_admission_authority
         BEGIN SELECT RAISE(ABORT, 'rejected'); END;",
    )?;
    assert_eq!(
        store.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::StorageIndeterminate)
    );
    Ok(())
}

#[test]
fn sqlite_unreadable_authority_table_is_storage_indeterminate() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let directory = tempfile::tempdir()?;
    let (store, path) = bootstrapped_sqlite(&directory, &signer)?;
    Connection::open(&path)?.execute_batch("DROP TABLE fork_admission_authority")?;
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::StorageIndeterminate)
    );
    Ok(())
}

#[test]
fn already_initialized_finalize_consumes_the_outstanding_challenge() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut stale = SqliteStore::open(&path)?;
    let mut winner = SqliteStore::open(&path)?;
    let challenge = stale.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_initialize(&challenge.canonical_bytes())?;
    bootstrap(&mut winner, &signer)?;
    assert_eq!(
        stale.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized)
    );

    // Even if the durable row later disappears, the rejected FAI1 stays spent.
    Connection::open(&path)?.execute_batch("DELETE FROM fork_admission_authority")?;
    assert_eq!(
        stale.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    assert_eq!(
        stale.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)
    );
    Ok(())
}

#[test]
fn sqlite_reopen_rejects_a_different_host_key_and_prior_sessions() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let other_signer = ForkHostSigningKeyV1::from_seed([8; 32])?;
    let directory = tempfile::tempdir()?;
    let (mut store, path) = bootstrapped_sqlite(&directory, &signer)?;
    let prior_session = open_policy_session(&mut store, &signer)?;
    store.advance_fork_admission_wall_fence(&prior_session)?;
    drop(store);

    let mut reopened = SqliteStore::open(&path)?;
    assert_eq!(
        reopened.begin_fork_admission_open(
            PublicKey::from_bytes(other_signer.public_key()),
            POLICY_DIGEST
        ),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    assert_eq!(
        reopened.advance_fork_admission_wall_fence(&prior_session),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    let session = open_policy_session(&mut reopened, &signer)?;
    reopened.advance_fork_admission_wall_fence(&session)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ADR-106 revision 3: admitted Fork erasure containment and parent visibility.
// ---------------------------------------------------------------------------

use pos_core::{ErasureGate as _, ErasureVerifiedInventoryQueryV1 as _};

type AdmissionResult = Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1>;

/// Every adapter capability the revision 3 acceptance vectors use.
trait AdmittedForkStore:
    EventStore
    + ForkAdmissionAuthorityBootstrapPortV1
    + ForkAdmissionAuthorityPortV1
    + pos_core::ErasureInventoryPersistencePortV1
    + pos_core::OwnTracksEnrollmentStore
    + pos_core::geo_admission::GeoLocationAdmissionStore
{
}

impl<T> AdmittedForkStore for T where
    T: EventStore
        + ForkAdmissionAuthorityBootstrapPortV1
        + ForkAdmissionAuthorityPortV1
        + pos_core::ErasureInventoryPersistencePortV1
        + pos_core::OwnTracksEnrollmentStore
        + pos_core::geo_admission::GeoLocationAdmissionStore
{
}

struct AdmittedForkFixture {
    host: ForkHostSigningKeyV1,
    adapter: ForkAuthenticationAdapterSigningKeyV1,
    policy: ForkAuthenticationPolicyV1,
    session: pos_store::ForkAdmissionAuthoritySessionV1,
}

impl AdmittedForkFixture {
    /// Provision FAH1, open a session and, when `bind_owner`, commit POC1.
    fn open<S: AdmittedForkStore>(
        store: &mut S,
        seed: u8,
        bind_owner: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let host = ForkHostSigningKeyV1::from_seed([seed; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([seed.wrapping_add(1); 32])?;
        let policy = authority_policy(&adapter)?;
        let session = open_session(store, &host, &policy)?;
        if bind_owner {
            let principal = principal_command(
                store,
                &host,
                &adapter,
                &policy,
                &session,
                [seed.wrapping_add(2); 32],
                u64::MAX,
                "owner",
            )?;
            store.execute_fork_admission_command(&session, &policy, &principal)?;
        }
        Ok(Self {
            host,
            adapter,
            policy,
            session,
        })
    }

    /// Build one host-signed FCC1 at cut zero.
    fn fork<S: ForkAdmissionAuthorityBootstrapPortV1>(
        &self,
        store: &S,
        operation: u8,
        parent: TimelineId,
        child_name: &str,
        expires_at: u64,
    ) -> Result<ForkAdmissionHostCommandV1, Box<dyn Error>> {
        let evidence =
            self.adapter
                .sign_authenticated_principal(AuthenticatedPrincipalRecordV1 {
                    principal: PrincipalRefV1::try_new([4; 16], "test.local")?,
                    adapter_id: "test-adapter".to_owned(),
                    assurance: 1,
                    issued_at: 0,
                    expires_at,
                    registry_binding: Hash::from_bytes([3; 32]),
                    operation_nonce: [5; 32],
                })?;
        let verified = verify_authenticated_principal_evidence_v1(&self.policy, evidence)?;
        let principal = principal_digest_v1(&verified.evidence().record().principal)?;
        let store_id = store.fork_admission_host_record()?.store_id();
        let inner = encode(&Value::Array(vec![
            Value::Text("FCC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(store_id.as_bytes().to_vec()),
            Value::Bytes(self.session.identity().as_bytes().to_vec()),
            Value::Bytes(vec![operation; 32]),
            Value::Bytes(verified.evidence().digest()?.as_bytes().to_vec()),
            Value::Bytes(principal.as_bytes().to_vec()),
            Value::Bytes(parent.inner().to_bytes().to_vec()),
            Value::Integer(0.into()),
            Value::Integer(0.into()),
            Value::Bytes(vec![8; 32]),
            Value::Bytes(vec![9; 32]),
            Value::Integer(1.into()),
            Value::Text(child_name.to_owned()),
        ]))?;
        let signature = self.host.sign_command(&inner, &verified)?;
        let fac1 = encode(&Value::Array(vec![
            Value::Text("FAC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(inner),
            Value::Bytes(verified.evidence().to_canonical_cbor()?),
            Value::Bytes(signature.as_bytes().to_vec()),
        ]))?;
        Ok(ForkAdmissionHostCommandV1::from_canonical_cbor(&fac1)?)
    }

    /// Execute through the unfenced ADR-106 method.
    fn execute<S: ForkAdmissionAuthorityPortV1>(
        &self,
        store: &mut S,
        command: &ForkAdmissionHostCommandV1,
    ) -> AdmissionResult {
        store.execute_fork_admission_command(&self.session, &self.policy, command)
    }

    /// Reconcile one FCC1 through lookup-only FRP1.
    fn recover<S: AdmittedForkStore>(
        &self,
        store: &mut S,
        operation: u8,
    ) -> Result<AdmissionResult, Box<dyn Error>> {
        let proof = recovery_proof(store, &self.host, &self.session, 2, [operation; 32])?;
        Ok(store.recover_fork_admission_command(&self.session, &proof))
    }

    /// Execute through the permit method inside `gate_pair.0`'s topology
    /// transition with a context minted by `gate_pair.1` for `target`, then
    /// publish the store's verified-empty successor inventory. Returns the
    /// adapter outcome and whether the gate published a successor.
    fn in_transition<S: AdmittedForkStore>(
        &self,
        store: &mut S,
        gate_pair: (&ErasureContainmentGateV1, &ErasureContainmentGateV1),
        target: (Hash, TimelineId),
        command: &ForkAdmissionHostCommandV1,
    ) -> (AdmissionResult, bool) {
        let (gate, minted_by) = gate_pair;
        let mut outcome = None;
        let mut transition = |permit: &pos_core::ErasureTopologyTransitionPermitV1| {
            let context = minted_by.admitted_fork_context(permit, target.0, target.1);
            let result = store.execute_fork_admission_command_in_topology_transition(
                &context,
                &self.session,
                &self.policy,
                command,
            );
            let committed = result.is_ok();
            outcome = Some(result);
            let successor = if committed {
                successor_inventory(store)
            } else {
                Err(pos_core::ErasureErrorV1::ProvenanceMissing)
            };
            successor.map(|inventory| (inventory, ()))
        };
        let published = gate
            .install_from_verified_inventory_transition(&mut transition)
            .is_ok();
        (
            outcome.unwrap_or(Err(
                pos_core::ForkAdmissionErrorV1::ErasureContainmentUnavailable,
            )),
            published,
        )
    }
}

fn successor_inventory<S: pos_core::ErasureInventoryPersistencePortV1>(
    store: &mut S,
) -> Result<pos_core::ErasureVerifiedInventoryV1, pos_core::ErasureErrorV1> {
    let snapshot = store.complete_erasure_inventory_snapshot(4)?;
    pos_core::ErasureVerifiedEmptyInventoryQueryV1::new(snapshot).verified_inventory(4)
}

fn admission_label(result: &AdmissionResult) -> String {
    match result {
        Ok(ForkAdmissionOperationResultV1::Fork(_)) => "fork".to_owned(),
        Ok(ForkAdmissionOperationResultV1::PrincipalOwner(_)) => "principal-owner".to_owned(),
        Err(error) => format!("{error:?}"),
    }
}

/// A Timeline that holds accepted geographic evidence.
fn geographic_parent<S: AdmittedForkStore>(store: &mut S) -> Result<TimelineId, Box<dyn Error>> {
    let timeline = store.create_timeline("r3-geographic-parent")?;
    let entity = EntityId::new();
    let consent = ([1; 32], 8, [2; 32]);
    store.pair_owntracks_enrollment(pos_core::OwnTracksEnrollmentRequestV1::new(
        timeline.id(),
        entity,
        pos_core::geo_admission::GeoLocationAdmissionFenceV1::new(7, consent, (1, false, 9)),
        [42; 32],
    ))?;
    let admitted = store.admit_geo_location(
        pos_core::geo_admission::GeoLocationAdmissionRequestV1::from_input(
            pos_core::geo_admission::GeoLocationAdmissionInputV1::new(
                timeline.id(),
                entity,
                CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
                7,
                consent,
                (1, false, 10),
                ([4; 32], [5; 32]),
            ),
        ),
    )?;
    if admitted.is_accepted() {
        Ok(timeline.id())
    } else {
        Err("geographic evidence was not admitted".into())
    }
}

/// Timelines, FAR1 rows, Fork operation rows, and the authority wall fence.
fn sqlite_graph_rows(path: &str) -> Result<[i64; 4], Box<dyn Error>> {
    let connection = Connection::open(path)?;
    let mut rows = [0; 4];
    for (slot, query) in rows.iter_mut().zip([
        "SELECT COUNT(*) FROM timelines",
        "SELECT COUNT(*) FROM fork_admissions",
        "SELECT COUNT(*) FROM fork_admission_operations WHERE kind = 2",
        "SELECT last_authority_wall_time FROM fork_admission_authority WHERE singleton = 1",
    ]) {
        *slot = connection.query_row(query, [], |row| row.get(0))?;
    }
    Ok(rows)
}

fn sqlite_store_at(
    directory: &tempfile::TempDir,
    name: &str,
) -> Result<(SqliteStore, String), Box<dyn Error>> {
    let path = directory.path().join(name).to_string_lossy().into_owned();
    Ok((SqliteStore::open(&path)?, path))
}

/// T1, T7, T8: permit-method containment, publication and exact recovery.
fn assert_admitted_fork_transition_contract<S: AdmittedForkStore>(
    store: &mut S,
) -> Result<Vec<String>, Box<dyn Error>> {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store.bind_erasure_gate(Arc::clone(&gate))?;
    let fixture = AdmittedForkFixture::open(store, 201, true)?;
    let frozen = store.create_timeline("r3-frozen-parent")?;
    let open = store.create_timeline("r3-open-parent")?;
    let gate_pair = (gate.as_ref(), gate.as_ref());
    let mut labels = Vec::new();

    gate.freeze_timeline_for_test(frozen.id());
    let contained = fixture.fork(store, 211, frozen.id(), "r3-contained-child", u64::MAX)?;
    let target = (Hash::from_bytes([211; 32]), frozen.id());
    let (result, published) = fixture.in_transition(store, gate_pair, target, &contained);
    labels.push(admission_label(&result));
    assert!(
        !published,
        "a rejected transition keeps the installed inventory"
    );
    assert!(gate.inventory_generation().is_err());
    labels.push(admission_label(&fixture.recover(store, 211)?));

    let admitted = fixture.fork(store, 212, open.id(), "r3-admitted-child", u64::MAX)?;
    let target = (Hash::from_bytes([212; 32]), open.id());
    let (result, published) = fixture.in_transition(store, gate_pair, target, &admitted);
    labels.push(admission_label(&result));
    let Ok(ForkAdmissionOperationResultV1::Fork(receipt)) = result else {
        return Err("the unaffected parent was not admitted".into());
    };
    assert!(published, "the successor generation is published first");
    assert_eq!(
        gate.authorize(
            receipt.child_id,
            pos_core::ErasureProtectedOperationV1::Read
        ),
        Ok(())
    );
    assert!(store.get_timeline(receipt.child_id)?.is_some());

    gate.freeze_timeline_for_test(open.id());
    let (retry, published) = fixture.in_transition(store, gate_pair, target, &admitted);
    assert_eq!(retry, Ok(ForkAdmissionOperationResultV1::Fork(receipt)));
    assert!(
        published,
        "an exact retry republishes the identical inventory"
    );
    // Publication replaced the fixture's frozen set; freeze the parent again.
    gate.freeze_timeline_for_test(open.id());
    assert_eq!(
        fixture.execute(store, &admitted),
        Ok(ForkAdmissionOperationResultV1::Fork(receipt))
    );
    assert_eq!(
        fixture.recover(store, 212)?,
        Ok(ForkAdmissionOperationResultV1::Fork(receipt))
    );
    let after_freeze = fixture.fork(store, 213, open.id(), "r3-after-freeze", u64::MAX)?;
    labels.push(admission_label(&fixture.execute(store, &after_freeze)));
    labels.push(admission_label(&fixture.recover(store, 213)?));
    Ok(labels)
}

#[test]
fn admitted_fork_transition_contract_has_adapter_parity() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (mut sqlite, _) = sqlite_store_at(&directory, "r3-transition.db")?;
    let memory = assert_admitted_fork_transition_contract(&mut MemoryStore::new())?;
    assert_eq!(
        memory,
        [
            "ParentErasureContained",
            "OperationMissing",
            "fork",
            "ParentErasureContained",
            "OperationMissing",
        ]
    );
    assert_eq!(
        assert_admitted_fork_transition_contract(&mut sqlite)?,
        memory
    );
    Ok(())
}

/// T3: an absent, geographic, or geographic-and-frozen parent is the same
/// `ParentChanged` on both methods, before any erasure decision.
fn assert_parent_visibility_precedes_containment<S: AdmittedForkStore>(
    store: &mut S,
) -> Result<Vec<String>, Box<dyn Error>> {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store.bind_erasure_gate(Arc::clone(&gate))?;
    let fixture = AdmittedForkFixture::open(store, 221, true)?;
    let geographic = geographic_parent(store)?;
    let gate_pair = (gate.as_ref(), gate.as_ref());
    let mut labels = Vec::new();
    for (operation, parent, freeze) in [
        (222, geographic, false),
        (223, TimelineId::new(), false),
        (224, geographic, true),
    ] {
        if freeze {
            gate.freeze_timeline_for_test(parent);
        }
        let command = fixture.fork(store, operation, parent, "r3-invisible-child", u64::MAX)?;
        labels.push(admission_label(&fixture.execute(store, &command)));
        let target = (Hash::from_bytes([operation; 32]), parent);
        let (result, published) = fixture.in_transition(store, gate_pair, target, &command);
        assert!(!published);
        labels.push(admission_label(&result));
        labels.push(admission_label(&fixture.recover(store, operation)?));
    }
    Ok(labels)
}

#[test]
fn invisible_parents_are_parent_changed_on_both_adapters() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (mut sqlite, _) = sqlite_store_at(&directory, "r3-visibility.db")?;
    let memory = assert_parent_visibility_precedes_containment(&mut MemoryStore::new())?;
    assert_eq!(
        memory,
        ["ParentChanged", "ParentChanged", "OperationMissing"].repeat(3)
    );
    assert_eq!(
        assert_parent_visibility_precedes_containment(&mut sqlite)?,
        memory
    );
    Ok(())
}

/// T4 and T5: without an available bound gate the unfenced method only
/// returns exact committed results or `ErasureContainmentUnavailable`.
fn assert_unfenced_forks_fail_closed_without_an_available_gate<S: AdmittedForkStore>(
    mut stores: impl FnMut(&str) -> Result<S, Box<dyn Error>>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut labels = Vec::new();
    // Default unbound fail-closed store.
    let mut unbound = stores("r3-unbound.db")?;
    let fixture = AdmittedForkFixture::open(&mut unbound, 231, true)?;
    let parent = unbound.create_timeline("r3-unbound-parent")?;
    let command = fixture.fork(&unbound, 232, parent.id(), "r3-unbound-child", u64::MAX)?;
    labels.push(admission_label(&fixture.execute(&mut unbound, &command)));
    labels.push(admission_label(&fixture.recover(&mut unbound, 232)?));

    // Poisoned gate.
    let mut poisoned = stores("r3-poisoned.db")?;
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    poisoned.bind_erasure_gate(Arc::clone(&gate))?;
    let fixture = AdmittedForkFixture::open(&mut poisoned, 233, true)?;
    let parent = poisoned.create_timeline("r3-poisoned-parent")?;
    gate.poison();
    let command = fixture.fork(&poisoned, 234, parent.id(), "r3-poisoned-child", u64::MAX)?;
    labels.push(admission_label(&fixture.execute(&mut poisoned, &command)));
    labels.push(admission_label(&fixture.recover(&mut poisoned, 234)?));
    Ok(labels)
}

/// T4, T5 and T6 on a store whose production gate requires topology permits.
fn assert_permit_requiring_store_contract<S: AdmittedForkStore>(
    store: &mut S,
) -> Result<Vec<String>, Box<dyn Error>> {
    let parent = store.create_timeline("r3-permit-parent")?;
    let gate = Arc::new(ErasureContainmentGateV1::new_fail_closed());
    store.bind_erasure_gate(Arc::clone(&gate))?;
    // T5: POC1 through the unfenced method still commits.
    let fixture = AdmittedForkFixture::open(store, 241, true)?;
    let gate_pair = (gate.as_ref(), gate.as_ref());
    let command = fixture.fork(store, 242, parent.id(), "r3-permit-child", u64::MAX)?;
    let target = (Hash::from_bytes([242; 32]), parent.id());
    let mut labels = Vec::new();
    // T4: no verified inventory is installed yet.
    let (result, published) = fixture.in_transition(store, gate_pair, target, &command);
    assert!(!published);
    labels.push(admission_label(&result));
    let inventory = successor_inventory(store)?;
    gate.install_verified_inventory(
        Arc::new(inventory),
        pos_core::ErasureRecoveryLimitsV1::from_maximum_requests(4)?,
    )?;
    // T5: an absent FCC1 through the unfenced method writes nothing.
    labels.push(admission_label(&fixture.execute(store, &command)));
    labels.push(admission_label(&fixture.recover(store, 242)?));
    // T6: POC1 through the permit method is not a topology mutation.
    let principal = principal_command(
        store,
        &fixture.host,
        &fixture.adapter,
        &fixture.policy,
        &fixture.session,
        [243; 32],
        u64::MAX,
        "owner",
    )?;
    let (result, _) = fixture.in_transition(store, gate_pair, target, &principal);
    labels.push(admission_label(&result));
    let (result, published) = fixture.in_transition(store, gate_pair, target, &command);
    assert!(published);
    labels.push(admission_label(&result));
    // T5: the committed FCC1 is still exactly recoverable without a permit.
    labels.push(admission_label(&fixture.execute(store, &command)));
    let later = fixture.fork(store, 244, parent.id(), "r3-permit-later", u64::MAX)?;
    labels.push(admission_label(&fixture.execute(store, &later)));
    Ok(labels)
}

#[test]
fn unfenced_forks_fail_closed_without_an_available_gate_on_both_adapters(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let memory =
        assert_unfenced_forks_fail_closed_without_an_available_gate(|_| Ok(MemoryStore::new()))?;
    assert_eq!(
        memory,
        ["ErasureContainmentUnavailable", "OperationMissing"].repeat(2)
    );
    let sqlite = assert_unfenced_forks_fail_closed_without_an_available_gate(|name| {
        sqlite_store_at(&directory, name).map(|(store, _)| store)
    })?;
    assert_eq!(sqlite, memory);

    let mut ungated = MemoryStore::new().without_erasure_gate();
    let fixture = AdmittedForkFixture::open(&mut ungated, 235, true)?;
    let parent = ungated.create_timeline("r3-ungated-parent")?;
    let command = fixture.fork(&ungated, 236, parent.id(), "r3-ungated-child", u64::MAX)?;
    assert_eq!(
        fixture.execute(&mut ungated, &command),
        Err(pos_core::ForkAdmissionErrorV1::ErasureContainmentUnavailable)
    );
    let (sqlite_ungated, _) = sqlite_store_at(&directory, "r3-ungated.db")?;
    let mut sqlite_ungated = sqlite_ungated.without_erasure_gate();
    let fixture = AdmittedForkFixture::open(&mut sqlite_ungated, 237, true)?;
    let parent = sqlite_ungated.create_timeline("r3-ungated-parent")?;
    let command = fixture.fork(
        &sqlite_ungated,
        238,
        parent.id(),
        "r3-ungated-child",
        u64::MAX,
    )?;
    assert_eq!(
        fixture.execute(&mut sqlite_ungated, &command),
        Err(pos_core::ForkAdmissionErrorV1::ErasureContainmentUnavailable)
    );
    Ok(())
}

#[test]
fn permit_requiring_stores_admit_forks_only_inside_a_verified_transition(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (mut sqlite, path) = sqlite_store_at(&directory, "r3-permit.db")?;
    let memory = assert_permit_requiring_store_contract(&mut MemoryStore::new())?;
    assert_eq!(
        memory,
        [
            "ErasureContainmentUnavailable",
            "ErasureContainmentUnavailable",
            "OperationMissing",
            "InvalidRequest",
            "fork",
            "fork",
            "ErasureContainmentUnavailable",
        ]
    );
    assert_eq!(assert_permit_requiring_store_contract(&mut sqlite)?, memory);
    let [timelines, far1, operations, _] = sqlite_graph_rows(&path)?;
    assert_eq!((timelines, far1, operations), (2, 1, 1));
    Ok(())
}

/// T6: the context must bind this FCC1, this gate and a bound store.
fn assert_context_binds_this_fcc1<S: AdmittedForkStore>(
    store: &mut S,
    unbound: &mut S,
) -> Result<Vec<String>, Box<dyn Error>> {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let foreign = ErasureContainmentGateV1::new_test_open();
    store.bind_erasure_gate(Arc::clone(&gate))?;
    let fixture = AdmittedForkFixture::open(store, 251, true)?;
    let parent = store.create_timeline("r3-context-parent")?;
    let other = store.create_timeline("r3-context-other")?;
    let command = fixture.fork(store, 252, parent.id(), "r3-context-child", u64::MAX)?;
    let operation = Hash::from_bytes([252; 32]);
    let mut labels = Vec::new();
    for (gate_pair, target) in [
        (
            (gate.as_ref(), gate.as_ref()),
            (Hash::from_bytes([253; 32]), parent.id()),
        ),
        ((gate.as_ref(), gate.as_ref()), (operation, other.id())),
        ((&foreign, &foreign), (operation, parent.id())),
        ((gate.as_ref(), &foreign), (operation, parent.id())),
    ] {
        let (result, published) = fixture.in_transition(store, gate_pair, target, &command);
        assert!(!published);
        labels.push(admission_label(&result));
    }
    labels.push(admission_label(&fixture.recover(store, 252)?));
    let unbound_fixture = AdmittedForkFixture::open(unbound, 254, true)?;
    let unbound_parent = unbound.create_timeline("r3-context-unbound-parent")?;
    let unbound_command = unbound_fixture.fork(
        unbound,
        255,
        unbound_parent.id(),
        "r3-unbound-child",
        u64::MAX,
    )?;
    let target = (Hash::from_bytes([255; 32]), unbound_parent.id());
    let (result, _) =
        unbound_fixture.in_transition(unbound, (&foreign, &foreign), target, &unbound_command);
    labels.push(admission_label(&result));
    Ok(labels)
}

#[test]
fn admitted_fork_context_binds_one_fcc1_on_both_adapters() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let memory = assert_context_binds_this_fcc1(&mut MemoryStore::new(), &mut MemoryStore::new())?;
    assert_eq!(
        memory,
        [
            "ErasureContainmentUnavailable",
            "ErasureContainmentUnavailable",
            "ErasureContainmentUnavailable",
            "ErasureContainmentUnavailable",
            "OperationMissing",
            "ErasureContainmentUnavailable",
        ]
    );
    let (mut sqlite, _) = sqlite_store_at(&directory, "r3-context.db")?;
    let (mut sqlite_unbound, _) = sqlite_store_at(&directory, "r3-context-unbound.db")?;
    assert_eq!(
        assert_context_binds_this_fcc1(&mut sqlite, &mut sqlite_unbound)?,
        memory
    );
    Ok(())
}

/// T10: under a frozen parent every earlier ADR-106 rule still wins.
fn assert_containment_precedence_under_a_frozen_parent<S: AdmittedForkStore>(
    store: &mut S,
    unbound_owner: &mut S,
) -> Result<Vec<String>, Box<dyn Error>> {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store.bind_erasure_gate(Arc::clone(&gate))?;
    let fixture = AdmittedForkFixture::open(store, 261, true)?;
    let parent = store.create_timeline("r3-precedence-parent")?;
    let stale = store.create_timeline("r3-precedence-stale")?;
    store.append(
        stale.id(),
        &[EventDraft::new(
            EntityId::new(),
            Kind::new("fork.admission.coverage"),
            CanonicalBytes::from_vec(b"advances the cut".to_vec()),
        )],
    )?;
    let committed = fixture.fork(store, 262, parent.id(), "r3-precedence-child", u64::MAX)?;
    let mut labels = vec![admission_label(&fixture.execute(store, &committed))];
    gate.freeze_timeline_for_test(parent.id());
    gate.freeze_timeline_for_test(stale.id());
    for command in [
        committed,
        fixture.fork(store, 262, parent.id(), "r3-unequal-child", u64::MAX)?,
        fixture.fork(store, 263, parent.id(), "r3-expired-child", 1)?,
        fixture.fork(store, 264, stale.id(), "r3-stale-child", u64::MAX)?,
    ] {
        labels.push(admission_label(&fixture.execute(store, &command)));
    }
    let unbound_gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    unbound_owner.bind_erasure_gate(Arc::clone(&unbound_gate))?;
    let unbound = AdmittedForkFixture::open(unbound_owner, 265, false)?;
    let unbound_parent = unbound_owner.create_timeline("r3-precedence-unbound")?;
    unbound_gate.freeze_timeline_for_test(unbound_parent.id());
    let missing_owner = unbound.fork(
        unbound_owner,
        266,
        unbound_parent.id(),
        "r3-unbound-child",
        u64::MAX,
    )?;
    labels.push(admission_label(
        &unbound.execute(unbound_owner, &missing_owner),
    ));
    Ok(labels)
}

#[test]
fn containment_follows_every_earlier_rule_on_both_adapters() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let memory = assert_containment_precedence_under_a_frozen_parent(
        &mut MemoryStore::new(),
        &mut MemoryStore::new(),
    )?;
    assert_eq!(
        memory,
        [
            "fork",
            "fork",
            "Conflict",
            "Unauthenticated",
            "ParentErasureContained",
            "InvalidRequest",
        ]
    );
    let (mut sqlite, _) = sqlite_store_at(&directory, "r3-precedence.db")?;
    let (mut sqlite_unbound, _) = sqlite_store_at(&directory, "r3-precedence-unbound.db")?;
    assert_eq!(
        assert_containment_precedence_under_a_frozen_parent(&mut sqlite, &mut sqlite_unbound)?,
        memory
    );
    Ok(())
}

#[test]
fn sqlite_committed_corruption_and_clock_rollback_precede_containment() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let (mut store, path) = sqlite_store_at(&directory, "r3-sqlite-precedence.db")?;
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store.bind_erasure_gate(Arc::clone(&gate))?;
    let fixture = AdmittedForkFixture::open(&mut store, 271, true)?;
    let parent = store.create_timeline("r3-sqlite-precedence-parent")?;
    let committed = fixture.fork(&store, 272, parent.id(), "r3-sqlite-child", u64::MAX)?;
    assert!(matches!(
        fixture.execute(&mut store, &committed),
        Ok(ForkAdmissionOperationResultV1::Fork(_))
    ));
    gate.freeze_timeline_for_test(parent.id());
    let connection = Connection::open(&path)?;
    connection.execute("UPDATE fork_admissions SET far1_cbor = X'00'", [])?;
    connection.execute(
        "UPDATE fork_admission_authority SET last_authority_wall_time = ?1 WHERE singleton = 1",
        params![i64::MAX],
    )?;
    drop(connection);
    let before = sqlite_graph_rows(&path)?;
    assert_eq!(
        fixture.execute(&mut store, &committed),
        Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    );
    let later = fixture.fork(&store, 273, parent.id(), "r3-sqlite-later", u64::MAX)?;
    assert_eq!(
        fixture.execute(&mut store, &later),
        Err(pos_core::ForkAdmissionErrorV1::ClockRollback)
    );
    assert_eq!(sqlite_graph_rows(&path)?, before);
    Ok(())
}

/// T11: a busy write lock is reported without a partial graph, the gate
/// fence is released, and the next transition admits the Fork.
#[test]
fn sqlite_admitted_fork_under_an_external_write_lock_releases_the_gate_fence(
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (mut store, path) = sqlite_store_at(&directory, "r3-lock.db")?;
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store.bind_erasure_gate(Arc::clone(&gate))?;
    let fixture = AdmittedForkFixture::open(&mut store, 281, true)?;
    let parent = store.create_timeline("r3-locked-parent")?;
    let command = fixture.fork(&store, 282, parent.id(), "r3-locked-child", u64::MAX)?;
    let gate_pair = (gate.as_ref(), gate.as_ref());
    let target = (Hash::from_bytes([282; 32]), parent.id());
    let before = sqlite_graph_rows(&path)?;
    let lock = Connection::open(&path)?;
    lock.execute_batch("BEGIN IMMEDIATE")?;
    let (locked, published) = fixture.in_transition(&mut store, gate_pair, target, &command);
    assert_eq!(
        locked,
        Err(pos_core::ForkAdmissionErrorV1::StorageIndeterminate)
    );
    assert!(!published);
    assert_eq!(
        fixture.execute(&mut store, &command),
        Err(pos_core::ForkAdmissionErrorV1::StorageIndeterminate)
    );
    lock.execute_batch("ROLLBACK")?;
    drop(lock);
    assert_eq!(sqlite_graph_rows(&path)?, before);
    assert_eq!(
        fixture.recover(&mut store, 282)?,
        Err(pos_core::ForkAdmissionErrorV1::OperationMissing)
    );
    let (admitted, published) = fixture.in_transition(&mut store, gate_pair, target, &command);
    assert!(matches!(
        admitted,
        Ok(ForkAdmissionOperationResultV1::Fork(_))
    ));
    assert!(published);
    Ok(())
}

/// T12: a committed admitted Fork survives close, reopen and a later freeze.
#[test]
fn sqlite_admitted_fork_is_recovered_after_reopen_and_freeze() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (mut store, path) = sqlite_store_at(&directory, "r3-reopen.db")?;
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    store.bind_erasure_gate(Arc::clone(&gate))?;
    let fixture = AdmittedForkFixture::open(&mut store, 291, true)?;
    let parent = store.create_timeline("r3-reopen-parent")?;
    let command = fixture.fork(&store, 292, parent.id(), "r3-reopen-child", u64::MAX)?;
    let target = (Hash::from_bytes([292; 32]), parent.id());
    let (committed, _) =
        fixture.in_transition(&mut store, (gate.as_ref(), gate.as_ref()), target, &command);
    let Ok(ForkAdmissionOperationResultV1::Fork(receipt)) = committed else {
        return Err("the admitted Fork did not commit".into());
    };
    drop(store);

    let mut reopened = SqliteStore::open(&path)?;
    let reopened_gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    reopened.bind_erasure_gate(Arc::clone(&reopened_gate))?;
    reopened_gate.freeze_timeline_for_test(parent.id());
    let session = reopen_session(&mut reopened, &fixture.host, &fixture.policy)?;
    let fixture = AdmittedForkFixture { session, ..fixture };
    let before = sqlite_graph_rows(&path)?;
    assert_eq!(
        fixture.recover(&mut reopened, 292)?,
        Ok(ForkAdmissionOperationResultV1::Fork(receipt))
    );
    let retry = fixture.fork(&reopened, 292, parent.id(), "r3-reopen-child", u64::MAX)?;
    assert_eq!(
        fixture.execute(&mut reopened, &retry),
        Ok(ForkAdmissionOperationResultV1::Fork(receipt))
    );
    assert_eq!(sqlite_graph_rows(&path)?, before);
    Ok(())
}
