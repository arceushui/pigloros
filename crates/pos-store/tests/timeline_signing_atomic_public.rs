#![cfg(feature = "sqlite")]

use std::sync::Arc;

use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, CoreError, EntityId, ErasureArtifactClassV1,
    ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1, Event, EventDraft,
    EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1,
    KeyRegistryStateV1, KeyRoleV1, Kind, PreparedSubjectAppendAuthorizationV1,
    RegisteredArtifactV1, SchemaVersion, Seq, SeqRange, Signature, TimelineEventEnvelopeErrorV1,
    TimelineEventEnvelopeInputV1, TimelineEventEnvelopeV1, TimelineEventVerificationV1,
};
use pos_crypto::{
    key_roles::{sign_timeline_event_for_registered_role, SigningKeyMaterial},
    signing::{generate_keypair, verifying_key_from_public_key},
    timeline_erasure::{evaluate_timeline_event_erasure_v1, TimelineEventErasureInputV1},
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

fn signing_fixture() -> Result<(SigningKeyMaterial, KeyIdentityV1, KeyRegistryStateV1), CoreError> {
    let (key, _) = generate_keypair();
    let material = SigningKeyMaterial::new(key);
    let identity = KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 1);
    let mut registry = KeyRegistryStateV1::new();
    registry
        .register_key(KeyRegistrationV1::new(
            identity,
            material.material_digest(),
            Some(material.public_verification_key()),
        ))
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    Ok((material, identity, registry))
}

fn draft(value: &'static [u8]) -> EventDraft {
    EventDraft::new(
        EntityId::new(),
        Kind::new("timeline.signed.v1"),
        CanonicalBytes::from_static(value),
    )
}

fn append_signed(
    store: &mut dyn EventStore,
    timeline: pos_core::TimelineId,
    registry: &KeyRegistryStateV1,
    identity: KeyIdentityV1,
    material: &SigningKeyMaterial,
    value: &'static [u8],
) -> Result<Event, CoreError> {
    let mut sign = |authorized: &mut KeyRegistryStateV1,
                    envelope: &TimelineEventEnvelopeV1,
                    payload: &CanonicalBytes| {
        sign_timeline_event_for_registered_role(authorized, material, envelope, payload)
            .map_err(|error| CoreError::Storage(error.to_string()))
    };
    store.append_timeline_signed_authorized(
        timeline,
        registry,
        draft(value),
        identity,
        material.material_digest(),
        material.public_verification_key(),
        &mut sign,
    )
}

fn registered_sign(
    material: &SigningKeyMaterial,
    authorized: &mut KeyRegistryStateV1,
    envelope: &TimelineEventEnvelopeV1,
    bytes: &CanonicalBytes,
) -> Result<Signature, CoreError> {
    sign_timeline_event_for_registered_role(authorized, material, envelope, bytes)
        .map_err(|error| CoreError::Storage(error.to_string()))
}

fn append_prepared(
    store: &mut dyn EventStore,
    timeline: pos_core::TimelineId,
    registry: &KeyRegistryStateV1,
    authorization: &PreparedSubjectAppendAuthorizationV1,
    prepare_payload: &mut dyn FnMut(
        &TimelineEventEnvelopeInputV1,
    ) -> Result<CanonicalBytes, CoreError>,
    sign: &mut dyn FnMut(
        &mut KeyRegistryStateV1,
        &TimelineEventEnvelopeV1,
        &CanonicalBytes,
    ) -> Result<Signature, CoreError>,
) -> Result<Event, CoreError> {
    store.append_prepared_subject_encrypted_timeline_signed(
        timeline,
        registry,
        draft(b"placeholder"),
        *authorization,
        prepare_payload,
        sign,
    )
}

/// Counts both crypto callbacks so a rejection can prove neither ran.
#[derive(Default)]
struct CallbackCounts {
    payload: std::cell::Cell<usize>,
    sign: std::cell::Cell<usize>,
}

impl CallbackCounts {
    fn append(
        &self,
        store: &mut dyn EventStore,
        timeline: pos_core::TimelineId,
        registry: &KeyRegistryStateV1,
        authorization: &PreparedSubjectAppendAuthorizationV1,
    ) -> Result<Event, CoreError> {
        let mut payload = |_: &TimelineEventEnvelopeInputV1| {
            self.payload.set(self.payload.get() + 1);
            Ok(CanonicalBytes::from_static(b"ciphertext"))
        };
        let mut sign =
            |_: &mut KeyRegistryStateV1, _: &TimelineEventEnvelopeV1, _: &CanonicalBytes| {
                self.sign.set(self.sign.get() + 1);
                Err(CoreError::Storage("signer must not run".to_owned()))
            };
        append_prepared(
            store,
            timeline,
            registry,
            authorization,
            &mut payload,
            &mut sign,
        )
    }

    fn assert_not_invoked(&self) {
        assert_eq!(self.payload.get(), 0, "payload callback ran");
        assert_eq!(self.sign.get(), 0, "sign callback ran");
    }
}

/// Reserve the next caller-owned nonce, as the ADR-097 ledger would before
/// AES-GCM runs. The store never rewinds this counter.
fn reserve_nonce(counter: &std::cell::Cell<u64>) -> u64 {
    let next = counter.get() + 1;
    counter.set(next);
    next
}

fn sealed_payload(nonce: u64) -> CanonicalBytes {
    CanonicalBytes::from_vec(nonce.to_be_bytes().to_vec())
}

fn exercise_prepared_append(store: &mut dyn EventStore) -> Result<(), Box<dyn std::error::Error>> {
    let (material, registry, timeline, authorization) = prepared_fixture(store, true)?;
    let mut payload = |input: &TimelineEventEnvelopeInputV1| {
        if input.origin_timeline_id != timeline || input.identity != authorization.signing_identity
        {
            return Err(CoreError::Storage("wrong prepared context".to_owned()));
        }
        Ok(CanonicalBytes::from_static(b"prepared"))
    };
    let mut sign = |authorized: &mut KeyRegistryStateV1,
                    envelope: &TimelineEventEnvelopeV1,
                    bytes: &CanonicalBytes| {
        registered_sign(&material, authorized, envelope, bytes)
    };
    let event = append_prepared(
        store,
        timeline,
        &registry,
        &authorization,
        &mut payload,
        &mut sign,
    )?;
    assert_eq!(event.payload, CanonicalBytes::from_static(b"prepared"));
    assert_eq!(event.schema_version, SchemaVersion::V1);
    assert_eq!(
        event.signature_identity,
        Some(authorization.signing_identity)
    );
    assert_eq!(store.read_own(timeline, SeqRange::all())?, vec![event]);
    Ok(())
}

#[test]
fn prepared_append_authorizes_both_identities_in_both_adapters(
) -> Result<(), Box<dyn std::error::Error>> {
    exercise_prepared_append(&mut MemoryStore::new())?;
    exercise_prepared_append(&mut SqliteStore::open_in_memory()?)
}

fn exercise_prepared_append_on_fork(
    store: &mut dyn EventStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let (material, registry, parent, authorization) = prepared_fixture(store, true)?;
    append_signed(
        store,
        parent,
        &registry,
        authorization.signing_identity,
        &material,
        b"parent",
    )?;
    let child = store.fork(parent, Seq::from_u64(1), "prepared-child")?;
    let mut payload = |input: &TimelineEventEnvelopeInputV1| {
        assert_eq!(input.origin_timeline_id, child.id());
        assert_eq!(input.origin_logical_seq, Seq::from_u64(2));
        Ok(CanonicalBytes::from_static(b"prepared-child"))
    };
    let mut sign = |authorized: &mut KeyRegistryStateV1,
                    envelope: &TimelineEventEnvelopeV1,
                    bytes: &CanonicalBytes| {
        registered_sign(&material, authorized, envelope, bytes)
    };
    let event = append_prepared(
        store,
        child.id(),
        &registry,
        &authorization,
        &mut payload,
        &mut sign,
    )?;
    assert_eq!(event.seq, Seq::from_u64(1));
    assert_eq!(
        event.origin.map(|origin| origin.origin_logical_seq),
        Some(Seq::from_u64(2))
    );
    Ok(())
}

#[test]
fn prepared_append_finalizes_fork_context_in_both_adapters(
) -> Result<(), Box<dyn std::error::Error>> {
    exercise_prepared_append_on_fork(&mut MemoryStore::new())?;
    exercise_prepared_append_on_fork(&mut SqliteStore::open_in_memory()?)
}

fn prepared_fixture(
    store: &mut dyn EventStore,
    save_registry: bool,
) -> Result<
    (
        SigningKeyMaterial,
        KeyRegistryStateV1,
        pos_core::TimelineId,
        PreparedSubjectAppendAuthorizationV1,
    ),
    Box<dyn std::error::Error>,
> {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let (material, signing_identity, mut registry) = signing_fixture()?;
    let encryption_identity =
        KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let encryption_material_digest = Hash::from_bytes([91; 32]);
    registry.register_key(KeyRegistrationV1::new(
        encryption_identity,
        encryption_material_digest,
        None,
    ))?;
    if save_registry {
        store.save_key_registry(&registry)?;
    }
    let timeline = store.create_timeline("prepared-boundaries")?.id();
    let authorization = PreparedSubjectAppendAuthorizationV1 {
        encryption_identity,
        encryption_material_digest,
        signing_identity,
        signing_material_digest: material.material_digest(),
        signing_public_key: material.public_verification_key(),
    };
    Ok((material, registry, timeline, authorization))
}

fn reject_prepared_authorization(
    store: &mut dyn EventStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_material, registry, timeline, authorization) = prepared_fixture(store, true)?;
    let calls = CallbackCounts::default();
    let wrong_encryption_role = PreparedSubjectAppendAuthorizationV1 {
        encryption_identity: authorization.signing_identity,
        encryption_material_digest: authorization.signing_material_digest,
        ..authorization
    };
    let wrong_signing_role = PreparedSubjectAppendAuthorizationV1 {
        signing_identity: authorization.encryption_identity,
        signing_material_digest: authorization.encryption_material_digest,
        ..authorization
    };
    let both_wrong = PreparedSubjectAppendAuthorizationV1 {
        signing_identity: authorization.encryption_identity,
        signing_material_digest: authorization.encryption_material_digest,
        ..wrong_encryption_role
    };
    // ADR-097 order: registry match, then subject encryption, then signing.
    for (expected_registry, request, expected) in [
        (
            &registry,
            wrong_encryption_role,
            "subject encryption authorization",
        ),
        (
            &registry,
            wrong_signing_role,
            "Timeline signing authorization",
        ),
        (&registry, both_wrong, "subject encryption authorization"),
        (
            &KeyRegistryStateV1::new(),
            both_wrong,
            "registry changed during",
        ),
    ] {
        let error = calls
            .append(store, timeline, expected_registry, &request)
            .err()
            .ok_or("invalid prepared authorization was accepted")?;
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?}, got {error}"
        );
    }
    calls.assert_not_invoked();
    assert!(store.read_own(timeline, SeqRange::all())?.is_empty());
    Ok(())
}

#[test]
fn prepared_append_rejects_wrong_roles_before_crypto_in_both_adapters(
) -> Result<(), Box<dyn std::error::Error>> {
    reject_prepared_authorization(&mut MemoryStore::new())?;
    reject_prepared_authorization(&mut SqliteStore::open_in_memory()?)
}

fn reject_prepared_missing_timeline(
    store: &mut dyn EventStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_material, registry, _timeline, authorization) = prepared_fixture(store, true)?;
    let missing = pos_core::TimelineId::new();
    let calls = CallbackCounts::default();
    let result = calls.append(store, missing, &registry, &authorization);
    assert!(matches!(result, Err(CoreError::TimelineNotFound(id)) if id == missing));
    calls.assert_not_invoked();
    Ok(())
}

#[test]
fn prepared_append_rejects_missing_timeline_before_callbacks_in_both_adapters(
) -> Result<(), Box<dyn std::error::Error>> {
    reject_prepared_missing_timeline(&mut MemoryStore::new())?;
    reject_prepared_missing_timeline(&mut SqliteStore::open_in_memory()?)
}

fn reject_prepared_missing_registry(
    store: &mut dyn EventStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_material, registry, timeline, authorization) = prepared_fixture(store, false)?;
    let calls = CallbackCounts::default();
    assert!(calls
        .append(store, timeline, &registry, &authorization)
        .is_err());
    calls.assert_not_invoked();
    assert!(store.read_own(timeline, SeqRange::all())?.is_empty());
    Ok(())
}

#[test]
fn prepared_append_rejects_missing_registry_before_callbacks_in_both_adapters(
) -> Result<(), Box<dyn std::error::Error>> {
    reject_prepared_missing_registry(&mut MemoryStore::new())?;
    reject_prepared_missing_registry(&mut SqliteStore::open_in_memory()?)
}

fn reject_prepared_pending_destruction(
    store: &mut dyn EventStore,
    encryption_role: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_material, registry, timeline, authorization) = prepared_fixture(store, true)?;
    let (identity, material_digest) = if encryption_role {
        (
            authorization.encryption_identity,
            authorization.encryption_material_digest,
        )
    } else {
        (
            authorization.signing_identity,
            authorization.signing_material_digest,
        )
    };
    let (_, pending) = store.begin_key_registry_destruction(KeyDestructionRequestV1::new(
        identity,
        material_digest,
        Hash::from_bytes([93; 32]),
    ))?;
    let calls = CallbackCounts::default();
    for expected in [&registry, &pending] {
        assert!(calls
            .append(store, timeline, expected, &authorization)
            .is_err());
    }
    calls.assert_not_invoked();
    assert!(store.read_own(timeline, SeqRange::all())?.is_empty());
    Ok(())
}

#[test]
fn prepared_append_rejects_pending_destruction_for_either_role(
) -> Result<(), Box<dyn std::error::Error>> {
    for encryption_role in [true, false] {
        reject_prepared_pending_destruction(&mut MemoryStore::new(), encryption_role)?;
        reject_prepared_pending_destruction(&mut SqliteStore::open_in_memory()?, encryption_role)?;
    }
    Ok(())
}

fn rotation_registration(encryption_role: bool) -> KeyRegistrationV1 {
    if encryption_role {
        KeyRegistrationV1::new(
            KeyIdentityV1::new("subject-owner", KeyRoleV1::SubjectDataEncryption, 2),
            Hash::from_bytes([94; 32]),
            None,
        )
    } else {
        let (key, _) = generate_keypair();
        let replacement = SigningKeyMaterial::new(key);
        KeyRegistrationV1::new(
            KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 2),
            replacement.material_digest(),
            Some(replacement.public_verification_key()),
        )
    }
}

fn reject_prepared_rotated_role(
    store: &mut dyn EventStore,
    encryption_role: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_material, mut registry, timeline, authorization) = prepared_fixture(store, true)?;
    registry.register_key(rotation_registration(encryption_role))?;
    store.save_key_registry(&registry)?;
    let calls = CallbackCounts::default();
    assert!(calls
        .append(store, timeline, &registry, &authorization)
        .is_err());
    calls.assert_not_invoked();
    assert!(store.read_own(timeline, SeqRange::all())?.is_empty());
    Ok(())
}

#[test]
fn prepared_append_rejects_rotated_epoch_for_either_role() -> Result<(), Box<dyn std::error::Error>>
{
    for encryption_role in [true, false] {
        reject_prepared_rotated_role(&mut MemoryStore::new(), encryption_role)?;
        reject_prepared_rotated_role(&mut SqliteStore::open_in_memory()?, encryption_role)?;
    }
    Ok(())
}

fn reject_prepared_callback_failures(
    store: &mut dyn EventStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let (material, registry, timeline, authorization) = prepared_fixture(store, true)?;
    let nonce = std::cell::Cell::new(0_u64);
    let sign_calls = std::cell::Cell::new(0_usize);
    let mut forged_sign =
        |_: &mut KeyRegistryStateV1, _: &TimelineEventEnvelopeV1, _: &CanonicalBytes| {
            sign_calls.set(sign_calls.get() + 1);
            Ok(Signature::from_bytes([0; 64]))
        };
    let mut failed_encryption = |_: &TimelineEventEnvelopeInputV1| {
        reserve_nonce(&nonce);
        Err(CoreError::Storage("encryption failed".to_owned()))
    };
    let mut sealed = |_: &TimelineEventEnvelopeInputV1| Ok(sealed_payload(reserve_nonce(&nonce)));
    let mut oversized = |_: &TimelineEventEnvelopeInputV1| {
        reserve_nonce(&nonce);
        Ok(CanonicalBytes::from_vec(vec![
            7;
            pos_core::MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1
                + 1
        ]))
    };
    let mut failed_sign =
        |_: &mut KeyRegistryStateV1, _: &TimelineEventEnvelopeV1, _: &CanonicalBytes| {
            Err(CoreError::Storage("signer failed".to_owned()))
        };
    // Each failure happens after the nonce reservation; the nonce stays spent.
    assert!(append_prepared(
        store,
        timeline,
        &registry,
        &authorization,
        &mut failed_encryption,
        &mut forged_sign,
    )
    .is_err());
    assert_eq!((nonce.get(), sign_calls.get()), (1, 0));
    assert!(append_prepared(
        store,
        timeline,
        &registry,
        &authorization,
        &mut sealed,
        &mut failed_sign,
    )
    .is_err());
    assert_eq!(nonce.get(), 2);
    assert!(append_prepared(
        store,
        timeline,
        &registry,
        &authorization,
        &mut oversized,
        &mut forged_sign,
    )
    .is_err());
    assert_eq!((nonce.get(), sign_calls.get()), (3, 0));
    // A forged signature is rejected by verification after signing ran.
    assert!(append_prepared(
        store,
        timeline,
        &registry,
        &authorization,
        &mut sealed,
        &mut forged_sign,
    )
    .is_err());
    assert_eq!((nonce.get(), sign_calls.get()), (4, 1));
    assert!(store.read_own(timeline, SeqRange::all())?.is_empty());
    let mut sign = |authorized: &mut KeyRegistryStateV1,
                    envelope: &TimelineEventEnvelopeV1,
                    bytes: &CanonicalBytes| {
        registered_sign(&material, authorized, envelope, bytes)
    };
    let committed = append_prepared(
        store,
        timeline,
        &registry,
        &authorization,
        &mut sealed,
        &mut sign,
    )?;
    // The retry reserves the next nonce; no rolled-back value is reused.
    assert_eq!(nonce.get(), 5);
    assert_eq!(committed.payload, sealed_payload(5));
    assert_eq!(store.read_own(timeline, SeqRange::all())?, vec![committed]);
    Ok(())
}

#[test]
fn prepared_append_rolls_back_failed_crypto_and_signature_in_both_adapters(
) -> Result<(), Box<dyn std::error::Error>> {
    reject_prepared_callback_failures(&mut MemoryStore::new())?;
    reject_prepared_callback_failures(&mut SqliteStore::open_in_memory()?)
}

#[test]
fn sqlite_prepared_append_rolls_back_insert_failure_and_allows_retry(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("prepared-insert.sqlite");
    let path = path.to_str().ok_or("temporary SQLite path is not UTF-8")?;
    let mut store = SqliteStore::open(path)?;
    let (material, registry, timeline, authorization) = prepared_fixture(&mut store, true)?;
    let connection = rusqlite::Connection::open(path)?;
    connection.execute_batch(
        "CREATE TRIGGER reject_prepared_insert BEFORE INSERT ON events
         BEGIN SELECT RAISE(ABORT, 'injected prepared insertion failure'); END;",
    )?;
    drop(connection);
    drop(store);
    let mut store = SqliteStore::open(path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let nonce = std::cell::Cell::new(0_u64);
    let mut payload = |_: &TimelineEventEnvelopeInputV1| Ok(sealed_payload(reserve_nonce(&nonce)));
    let mut sign = |authorized: &mut KeyRegistryStateV1,
                    envelope: &TimelineEventEnvelopeV1,
                    bytes: &CanonicalBytes| {
        registered_sign(&material, authorized, envelope, bytes)
    };
    assert!(append_prepared(
        &mut store,
        timeline,
        &registry,
        &authorization,
        &mut payload,
        &mut sign,
    )
    .is_err());
    assert!(store.read_own(timeline, SeqRange::all())?.is_empty());
    assert_eq!(store.load_key_registry()?, Some(registry.clone()));
    // The insertion rollback does not return the reserved nonce.
    assert_eq!(nonce.get(), 1);
    drop(store);

    let connection = rusqlite::Connection::open(path)?;
    connection.execute_batch("DROP TRIGGER reject_prepared_insert")?;
    drop(connection);
    let mut store = SqliteStore::open(path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let committed = append_prepared(
        &mut store,
        timeline,
        &registry,
        &authorization,
        &mut payload,
        &mut sign,
    )?;
    assert_eq!(committed.seq, Seq::from_u64(1));
    assert_eq!(nonce.get(), 2);
    assert_eq!(committed.payload, sealed_payload(2));
    assert_eq!(store.read_own(timeline, SeqRange::all())?, vec![committed]);
    Ok(())
}

// MemoryStore needs no lifecycle race test: its prepared append takes
// `&mut self`, so the borrow checker statically forbids any other handle from
// rotating or destroying a key while the append is between authorization and
// commit. SQLite connections are independent handles, so the race is real
// there and `BEGIN IMMEDIATE` must serialize it.
#[derive(Clone, Copy, Debug)]
enum LifecycleContender {
    DestroySubject,
    DestroySigning,
    RotateSubject,
    RotateSigning,
}

fn contend_lifecycle(
    store: &mut SqliteStore,
    contender: LifecycleContender,
    registry: &KeyRegistryStateV1,
    authorization: &PreparedSubjectAppendAuthorizationV1,
) -> Result<KeyRegistryStateV1, CoreError> {
    let destroyed = match contender {
        LifecycleContender::DestroySubject => Some((
            authorization.encryption_identity,
            authorization.encryption_material_digest,
        )),
        LifecycleContender::DestroySigning => Some((
            authorization.signing_identity,
            authorization.signing_material_digest,
        )),
        LifecycleContender::RotateSubject | LifecycleContender::RotateSigning => None,
    };
    if let Some((identity, digest)) = destroyed {
        return store
            .begin_key_registry_destruction(KeyDestructionRequestV1::new(
                identity,
                digest,
                Hash::from_bytes([93; 32]),
            ))
            .map(|(_, pending)| pending);
    }
    let mut rotated = registry.clone();
    rotated
        .register_key(rotation_registration(matches!(
            contender,
            LifecycleContender::RotateSubject
        )))
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    store.save_key_registry(&rotated).map(|()| rotated)
}

fn pause_for_contender(
    entered: &std::sync::mpsc::Sender<()>,
    release: &std::sync::mpsc::Receiver<()>,
) -> Result<(), CoreError> {
    entered
        .send(())
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    release
        .recv()
        .map_err(|error| CoreError::Storage(error.to_string()))
}

/// Whether another connection holds the database write lock: a zero-timeout
/// `BEGIN IMMEDIATE` on a fresh probe connection must fail with `SQLITE_BUSY`.
fn write_lock_is_held(path: &str) -> Result<bool, CoreError> {
    let probe =
        rusqlite::Connection::open(path).map_err(|error| CoreError::Storage(error.to_string()))?;
    probe
        .busy_timeout(std::time::Duration::ZERO)
        .map_err(|error| CoreError::Storage(error.to_string()))?;
    let held = match probe.execute_batch("BEGIN IMMEDIATE") {
        Ok(()) => {
            probe
                .execute_batch("ROLLBACK")
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            false
        }
        Err(error) => error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy),
    };
    Ok(held)
}

struct PreparedRaceOutcome {
    appended: Result<Event, CoreError>,
    lifecycle: Result<KeyRegistryStateV1, CoreError>,
    /// The contender reached its lifecycle call while the append held the
    /// write lock, and had not completed when the append was released.
    lifecycle_blocked: bool,
}

fn run_prepared_lifecycle_race(
    path: &str,
    material: SigningKeyMaterial,
    registry: &KeyRegistryStateV1,
    timeline: pos_core::TimelineId,
    authorization: &PreparedSubjectAppendAuthorizationV1,
    contender: LifecycleContender,
    pause_in_sign: bool,
) -> Result<PreparedRaceOutcome, Box<dyn std::error::Error>> {
    let mut append_store = SqliteStore::open(path)?;
    append_store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    // Lifecycle writes on an unbound handle need no erasure inventory fence,
    // so only the append store's `BEGIN IMMEDIATE` can hold this contender back.
    let mut lifecycle_store = SqliteStore::open(path)?;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let outcome = std::thread::scope(|scope| -> Result<_, CoreError> {
        let appending = scope.spawn(move || {
            let mut payload =
                |_: &TimelineEventEnvelopeInputV1| -> Result<CanonicalBytes, CoreError> {
                    if !pause_in_sign {
                        pause_for_contender(&entered_tx, &release_rx)?;
                    }
                    Ok(CanonicalBytes::from_static(b"ciphertext"))
                };
            let mut sign = |authorized: &mut KeyRegistryStateV1,
                            envelope: &TimelineEventEnvelopeV1,
                            bytes: &CanonicalBytes|
             -> Result<Signature, CoreError> {
                if pause_in_sign {
                    pause_for_contender(&entered_tx, &release_rx)?;
                }
                registered_sign(&material, authorized, envelope, bytes)
            };
            append_prepared(
                &mut append_store,
                timeline,
                registry,
                authorization,
                &mut payload,
                &mut sign,
            )
        });
        entered_rx
            .recv()
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let lifecycle = scope.spawn(move || {
            attempt_tx
                .send(())
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            let result =
                contend_lifecycle(&mut lifecycle_store, contender, registry, authorization);
            done_tx
                .send(())
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            result
        });
        // The contender signals immediately before its destroy/rotate call.
        // While the paused append holds `BEGIN IMMEDIATE`, a probe proves the
        // write lock is taken, so the contender cannot have committed yet.
        let attempted = attempt_rx.recv().is_ok();
        let lock_probe = write_lock_is_held(path);
        let not_completed = done_rx.try_recv().is_err();
        // Release before propagating a probe error so the scope can join.
        release_tx
            .send(())
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        let lifecycle_blocked = attempted && lock_probe? && not_completed;
        let appended = appending
            .join()
            .map_err(|_| CoreError::Storage("append thread panicked".to_owned()))?;
        let lifecycle = lifecycle
            .join()
            .map_err(|_| CoreError::Storage("lifecycle thread panicked".to_owned()))?;
        Ok(PreparedRaceOutcome {
            appended,
            lifecycle,
            lifecycle_blocked,
        })
    })?;
    Ok(outcome)
}

fn assert_prepared_lifecycle_race(
    contender: LifecycleContender,
    pause_in_sign: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("prepared-lifecycle-race.sqlite");
    let path = path.to_str().ok_or("temporary SQLite path is not UTF-8")?;
    let mut setup = SqliteStore::open(path)?;
    let (material, registry, timeline, authorization) = prepared_fixture(&mut setup, true)?;
    drop(setup);
    let outcome = run_prepared_lifecycle_race(
        path,
        material,
        &registry,
        timeline,
        &authorization,
        contender,
        pause_in_sign,
    )?;
    assert!(
        outcome.lifecycle_blocked,
        "{contender:?} was not blocked by the prepared append's write lock"
    );
    let appended = outcome.appended?;
    let updated = outcome.lifecycle?;
    assert_eq!(
        appended.signature_identity,
        Some(authorization.signing_identity)
    );

    let mut reopened = SqliteStore::open(path)?;
    reopened.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    assert_eq!(reopened.load_key_registry()?, Some(updated.clone()));
    // After the lifecycle change commits, neither the stale nor the updated
    // registry authorizes another append with the old identities.
    let calls = CallbackCounts::default();
    for expected in [&registry, &updated] {
        assert!(calls
            .append(&mut reopened, timeline, expected, &authorization)
            .is_err());
    }
    calls.assert_not_invoked();
    assert_eq!(
        reopened.read_own(timeline, SeqRange::all())?,
        vec![appended]
    );
    Ok(())
}

#[test]
fn sqlite_prepared_append_fixes_both_identities_through_commit(
) -> Result<(), Box<dyn std::error::Error>> {
    for contender in [
        LifecycleContender::DestroySubject,
        LifecycleContender::DestroySigning,
        LifecycleContender::RotateSubject,
        LifecycleContender::RotateSigning,
    ] {
        for pause_in_sign in [false, true] {
            assert_prepared_lifecycle_race(contender, pause_in_sign)?;
        }
    }
    Ok(())
}

const fn timeline_artifact(
    digest: u8,
    data_class: ArtifactDataClassV1,
    transition_rule: ArtifactTransitionRuleV1,
    state: ArtifactStateV1,
) -> ArtifactClaimInputV1 {
    ArtifactClaimInputV1 {
        registration: RegisteredArtifactV1::new(
            ErasureArtifactClassV1::TimelineReplay,
            ErasureReferenceV1::from_digest([digest; 32]),
            data_class,
            None,
            ErasureReferenceV1::from_digest([113; 32]),
            ArtifactOptionalityV1::Required,
            transition_rule,
        ),
        current_claim: ErasureReplayClaimV1::Exact,
        state,
    }
}

fn exercise_public_read_erasure_report(
    store: &mut dyn EventStore,
) -> Result<(), Box<dyn std::error::Error>> {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let (material, identity, registry) = signing_fixture()?;
    store.save_key_registry(&registry)?;
    let timeline = store.create_timeline("erasure-report")?;
    append_signed(
        store,
        timeline.id(),
        &registry,
        identity,
        &material,
        b"retained",
    )?;
    let event = store.read(timeline.id(), SeqRange::all())?.remove(0);
    let registry = store.load_key_registry()?.ok_or("missing key registry")?;
    let payload = timeline_artifact(
        111,
        ArtifactDataClassV1::PrivateSubjectData,
        ArtifactTransitionRuleV1::RetainStructure,
        ArtifactStateV1::Retained,
    );
    let context = timeline_artifact(
        112,
        ArtifactDataClassV1::StructuralAuditMetadata,
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactStateV1::Retained,
    );
    let report = evaluate_timeline_event_erasure_v1(TimelineEventErasureInputV1 {
        event: Some(&event),
        registry: Some(&registry),
        trust_anchor: Some((identity, material.public_verification_key())),
        enclosing_claim: ErasureReplayClaimV1::Exact,
        payload_artifact: payload,
        signed_context_artifact: context,
    })?;
    assert_eq!(report.verification(), TimelineEventVerificationV1::Verified);
    assert_eq!(report.replay_claim(), ErasureReplayClaimV1::Exact);

    let mut erased_payload = payload;
    erased_payload.state = ArtifactStateV1::TransitionApplied;
    let report = evaluate_timeline_event_erasure_v1(TimelineEventErasureInputV1 {
        event: Some(&event),
        registry: Some(&registry),
        trust_anchor: Some((identity, material.public_verification_key())),
        enclosing_claim: ErasureReplayClaimV1::Exact,
        payload_artifact: erased_payload,
        signed_context_artifact: context,
    })?;
    assert_eq!(
        report.verification(),
        TimelineEventVerificationV1::MissingRequiredContext
    );
    assert_eq!(report.replay_claim(), ErasureReplayClaimV1::StructuralOnly);
    Ok(())
}

#[test]
fn public_store_reads_feed_erasure_aware_verification() -> Result<(), Box<dyn std::error::Error>> {
    exercise_public_read_erasure_report(&mut MemoryStore::new())?;
    exercise_public_read_erasure_report(&mut SqliteStore::open_in_memory()?)?;
    Ok(())
}

fn exercise_signed_fork(store: &mut dyn EventStore) -> Result<(), Box<dyn std::error::Error>> {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let (material, identity, registry) = signing_fixture()?;
    store.save_key_registry(&registry)?;
    let root = store.create_timeline("signed-root")?;
    let first = append_signed(store, root.id(), &registry, identity, &material, b"root")?;
    assert_eq!(first.seq, Seq::from_u64(1));
    assert_eq!(
        first
            .origin
            .ok_or("missing root origin")?
            .origin_logical_seq,
        first.seq
    );
    let child = store.fork(root.id(), Seq::from_u64(1), "signed-child")?;
    let second = append_signed(store, child.id(), &registry, identity, &material, b"child")?;
    assert_eq!(second.seq, Seq::from_u64(1));
    let child_origin = second.origin.ok_or("missing child origin")?;
    assert_eq!(child_origin.origin_timeline_id, child.id());
    assert_eq!(child_origin.origin_logical_seq, Seq::from_u64(2));

    let verifying_key = verifying_key_from_public_key(&material.public_verification_key())?;
    for event in store.read(child.id(), SeqRange::all())? {
        let envelope = TimelineEventEnvelopeV1::from_committed_event(&event)?;
        let signature = event
            .signature
            .as_ref()
            .ok_or("missing committed signature")?;
        pos_crypto::key_roles::verify_timeline_event_for_role(
            &verifying_key,
            identity,
            &envelope,
            &event.payload,
            signature,
        )?;
    }
    assert_eq!(store.read(child.id(), SeqRange::all())?.len(), 2);
    Ok(())
}

#[test]
fn both_adapters_commit_exact_root_and_fork_envelope_signatures(
) -> Result<(), Box<dyn std::error::Error>> {
    exercise_signed_fork(&mut MemoryStore::new())?;
    exercise_signed_fork(&mut SqliteStore::open_in_memory()?)?;
    Ok(())
}

#[test]
fn committed_envelope_rejects_missing_or_modified_first_commit_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = MemoryStore::new();
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let (material, identity, registry) = signing_fixture()?;
    store.save_key_registry(&registry)?;
    let timeline = store.create_timeline("signed-context")?;
    let event = append_signed(
        &mut store,
        timeline.id(),
        &registry,
        identity,
        &material,
        b"original",
    )?;

    let mut missing_identity = event.clone();
    missing_identity.signature_identity = None;
    assert_eq!(
        TimelineEventEnvelopeV1::from_committed_event(&missing_identity),
        Err(TimelineEventEnvelopeErrorV1::InvalidIdentity)
    );

    let mut missing_origin = event.clone();
    missing_origin.origin = None;
    assert_eq!(
        TimelineEventEnvelopeV1::from_committed_event(&missing_origin),
        Err(TimelineEventEnvelopeErrorV1::FieldOutOfBounds)
    );

    let mut invalid_origin = event.clone();
    invalid_origin.origin = event.origin.map(|mut origin| {
        origin.origin_logical_seq = Seq::ZERO;
        origin
    });
    assert_eq!(
        TimelineEventEnvelopeV1::from_committed_event(&invalid_origin),
        Err(TimelineEventEnvelopeErrorV1::FieldOutOfBounds)
    );

    let mut altered_payload = event.clone();
    altered_payload.payload = CanonicalBytes::from_static(b"altered");
    assert_eq!(
        TimelineEventEnvelopeV1::from_committed_event(&altered_payload),
        Err(TimelineEventEnvelopeErrorV1::PayloadHashMismatch)
    );

    let mut altered_hash = event;
    altered_hash.payload_hash = Hash::zero();
    assert_eq!(
        TimelineEventEnvelopeV1::from_committed_event(&altered_hash),
        Err(TimelineEventEnvelopeErrorV1::PayloadHashMismatch)
    );
    Ok(())
}

struct WrongPayloadHasher;

impl pos_core::hasher::Hasher for WrongPayloadHasher {
    fn genesis_hash(&self) -> Hash {
        pos_core::hasher::Hasher::genesis_hash(&pos_crypto::chain::Blake3Hasher)
    }

    fn hash_payload(&self, _: &CanonicalBytes) -> Hash {
        Hash::zero()
    }

    fn hash_event(
        &self,
        previous_hash: &Hash,
        event_id_bytes: &[u8],
        payload: &CanonicalBytes,
    ) -> Hash {
        pos_core::hasher::Hasher::hash_event(
            &pos_crypto::chain::Blake3Hasher,
            previous_hash,
            event_id_bytes,
            payload,
        )
    }
}

fn reject_mismatched_payload_hasher(
    store: &mut dyn EventStore,
) -> Result<(), Box<dyn std::error::Error>> {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let (material, identity, registry) = signing_fixture()?;
    store.save_key_registry(&registry)?;
    let timeline = store.create_timeline("wrong-hash")?;
    let calls = std::cell::Cell::new(0);
    let mut sign = |_: &mut KeyRegistryStateV1, _: &TimelineEventEnvelopeV1, _: &CanonicalBytes| {
        calls.set(calls.get() + 1);
        Err(CoreError::Storage("signer must not run".to_owned()))
    };
    assert!(store
        .append_timeline_signed_authorized(
            timeline.id(),
            &registry,
            draft(b"wrong-hash"),
            identity,
            material.material_digest(),
            material.public_verification_key(),
            &mut sign,
        )
        .is_err());
    assert_eq!(calls.get(), 0);
    assert!(store.read_own(timeline.id(), SeqRange::all())?.is_empty());
    Ok(())
}

#[test]
fn both_adapters_reject_a_hasher_that_disagrees_with_the_envelope(
) -> Result<(), Box<dyn std::error::Error>> {
    reject_mismatched_payload_hasher(&mut MemoryStore::with_hasher(Box::new(WrongPayloadHasher)))?;
    reject_mismatched_payload_hasher(&mut SqliteStore::open_in_memory_with_hasher(Box::new(
        WrongPayloadHasher,
    ))?)?;
    Ok(())
}

fn exercise_failed_signing(store: &mut dyn EventStore) -> Result<(), Box<dyn std::error::Error>> {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let (material, identity, registry) = signing_fixture()?;
    store.save_key_registry(&registry)?;
    let timeline = store.create_timeline("failed-signing")?;
    let mut sign_calls = 0;
    let mut bad_signature =
        |_: &mut KeyRegistryStateV1, _: &TimelineEventEnvelopeV1, _: &CanonicalBytes| {
            sign_calls += 1;
            Ok(Signature::from_bytes([0; 64]))
        };
    assert!(store
        .append_timeline_signed_authorized(
            timeline.id(),
            &registry,
            draft(b"bad-signature"),
            identity,
            material.material_digest(),
            material.public_verification_key(),
            &mut bad_signature,
        )
        .is_err());
    assert_eq!(sign_calls, 1);
    assert!(store.read_own(timeline.id(), SeqRange::all())?.is_empty());

    let mut rejected =
        |_: &mut KeyRegistryStateV1, _: &TimelineEventEnvelopeV1, _: &CanonicalBytes| {
            Err(CoreError::Storage("signer failed".to_owned()))
        };
    assert!(store
        .append_timeline_signed_authorized(
            timeline.id(),
            &registry,
            draft(b"signer-failure"),
            identity,
            material.material_digest(),
            material.public_verification_key(),
            &mut rejected,
        )
        .is_err());
    assert!(store.read_own(timeline.id(), SeqRange::all())?.is_empty());

    let oversized = vec![7; pos_core::MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1 + 1];
    let unexpected_calls = std::cell::Cell::new(0);
    let mut not_called =
        |_: &mut KeyRegistryStateV1, _: &TimelineEventEnvelopeV1, _: &CanonicalBytes| {
            unexpected_calls.set(unexpected_calls.get() + 1);
            Err(CoreError::Storage("signer must not run".to_owned()))
        };
    assert!(store
        .append_timeline_signed_authorized(
            timeline.id(),
            &registry,
            EventDraft::new(
                EntityId::new(),
                Kind::new("timeline.signed.v1"),
                CanonicalBytes::from_vec(oversized),
            ),
            identity,
            material.material_digest(),
            material.public_verification_key(),
            &mut not_called,
        )
        .is_err());
    assert!(store.read_own(timeline.id(), SeqRange::all())?.is_empty());

    let request = KeyDestructionRequestV1::new(
        identity,
        material.material_digest(),
        pos_core::Hash::from_bytes([89; 32]),
    );
    let (_, pending) = store.begin_key_registry_destruction(request)?;
    assert!(store
        .append_timeline_signed_authorized(
            timeline.id(),
            &pending,
            draft(b"destroy-pending"),
            identity,
            material.material_digest(),
            material.public_verification_key(),
            &mut not_called,
        )
        .is_err());
    assert!(store.read_own(timeline.id(), SeqRange::all())?.is_empty());
    assert_eq!(unexpected_calls.get(), 0);
    Ok(())
}

#[test]
fn both_adapters_rollback_failed_or_unauthorized_signing() -> Result<(), Box<dyn std::error::Error>>
{
    exercise_failed_signing(&mut MemoryStore::new())?;
    exercise_failed_signing(&mut SqliteStore::open_in_memory()?)?;
    Ok(())
}

fn exercise_signing_boundary_failures(
    store: &mut dyn EventStore,
) -> Result<(), Box<dyn std::error::Error>> {
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let (material, identity, registry) = signing_fixture()?;
    let timeline = store.create_timeline("signing-boundaries")?;

    assert!(append_signed(
        store,
        timeline.id(),
        &registry,
        identity,
        &material,
        b"missing-registry",
    )
    .is_err());
    store.save_key_registry(&registry)?;
    assert!(append_signed(
        store,
        timeline.id(),
        &KeyRegistryStateV1::new(),
        identity,
        &material,
        b"stale-registry",
    )
    .is_err());
    assert!(append_signed(
        store,
        pos_core::TimelineId::new(),
        &registry,
        identity,
        &material,
        b"missing-timeline",
    )
    .is_err());
    assert!(store.read_own(timeline.id(), SeqRange::all())?.is_empty());

    let committed = append_signed(
        store,
        timeline.id(),
        &registry,
        identity,
        &material,
        b"committed",
    )?;
    let mut legacy_callback = move |_: &KeyRegistryStateV1, seq: Seq| {
        let mut event = committed.clone();
        event.seq = seq;
        Ok(event)
    };
    let rejected = store.append_signed_authorized(timeline.id(), &registry, &mut legacy_callback);
    assert!(rejected
        .err()
        .is_some_and(|error| error.to_string().contains("atomic envelope append seam")));
    assert_eq!(store.read_own(timeline.id(), SeqRange::all())?.len(), 1);
    Ok(())
}

#[test]
fn both_adapters_fail_closed_at_atomic_signing_boundaries() -> Result<(), Box<dyn std::error::Error>>
{
    exercise_signing_boundary_failures(&mut MemoryStore::new())?;
    exercise_signing_boundary_failures(&mut SqliteStore::open_in_memory()?)?;
    Ok(())
}

#[test]
fn sqlite_insert_failure_discards_signed_event_and_allows_retry(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("signed-insert.sqlite");
    let path = path.to_str().ok_or("temporary SQLite path is not UTF-8")?;
    let mut store = SqliteStore::open(path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let (material, identity, registry) = signing_fixture()?;
    store.save_key_registry(&registry)?;
    let timeline = store.create_timeline("signed-insert-failure")?;
    let connection = rusqlite::Connection::open(path)?;
    connection.execute_batch(
        "CREATE TRIGGER reject_signed_insert BEFORE INSERT ON events
         BEGIN SELECT RAISE(ABORT, 'injected signed insertion failure'); END;",
    )?;
    drop(connection);
    drop(store);
    let mut store = SqliteStore::open(path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;

    assert!(append_signed(
        &mut store,
        timeline.id(),
        &registry,
        identity,
        &material,
        b"first-attempt",
    )
    .is_err());
    assert!(store.read_own(timeline.id(), SeqRange::all())?.is_empty());
    assert_eq!(store.load_key_registry()?, Some(registry.clone()));

    let connection = rusqlite::Connection::open(path)?;
    connection.execute_batch("DROP TRIGGER reject_signed_insert")?;
    drop(connection);
    drop(store);
    let mut store = SqliteStore::open(path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let committed = append_signed(
        &mut store,
        timeline.id(),
        &registry,
        identity,
        &material,
        b"retry",
    )?;
    assert_eq!(committed.seq, Seq::from_u64(1));
    assert_eq!(
        store.read_own(timeline.id(), SeqRange::all())?,
        vec![committed]
    );
    Ok(())
}

#[test]
fn sqlite_rotation_waits_until_signed_event_commit() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("sign-and-rotate.sqlite");
    let path = path.to_str().ok_or("temporary SQLite path is not UTF-8")?;
    let (material, identity, registry) = signing_fixture()?;
    let mut setup = SqliteStore::open(path)?;
    setup.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    setup.save_key_registry(&registry)?;
    let timeline = setup.create_timeline("sign-before-rotation")?;
    drop(setup);

    let (replacement_key, _) = generate_keypair();
    let replacement = SigningKeyMaterial::new(replacement_key);
    let next_identity =
        KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 2);
    let mut rotated = registry.clone();
    rotated.register_key(KeyRegistrationV1::new(
        next_identity,
        replacement.material_digest(),
        Some(replacement.public_verification_key()),
    ))?;
    let mut signing_store = SqliteStore::open(path)?;
    signing_store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let mut rotation_store = SqliteStore::open(path)?;
    rotation_store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
    let (rotation_done_tx, rotation_done_rx) = std::sync::mpsc::channel();
    let expected = registry.clone();
    let proposed = rotated.clone();
    let timeline_id = timeline.id();
    let public_key = material.public_verification_key();
    let material_digest = material.material_digest();
    let (signed, rotation_result, rotation_waited) =
        std::thread::scope(|scope| -> Result<_, CoreError> {
            let signing = scope.spawn(move || {
                let mut sign = |authorized: &mut KeyRegistryStateV1,
                                envelope: &TimelineEventEnvelopeV1,
                                payload: &CanonicalBytes| {
                    entered_tx
                        .send(())
                        .map_err(|error| CoreError::Storage(error.to_string()))?;
                    release_rx
                        .recv()
                        .map_err(|error| CoreError::Storage(error.to_string()))?;
                    sign_timeline_event_for_registered_role(
                        authorized, &material, envelope, payload,
                    )
                    .map_err(|error| CoreError::Storage(error.to_string()))
                };
                signing_store.append_timeline_signed_authorized(
                    timeline_id,
                    &expected,
                    draft(b"before-rotation"),
                    identity,
                    material_digest,
                    public_key,
                    &mut sign,
                )
            });
            entered_rx
                .recv()
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            let rotation = scope.spawn(move || {
                attempt_tx
                    .send(())
                    .map_err(|error| CoreError::Storage(error.to_string()))?;
                let result = rotation_store.save_key_registry(&proposed);
                rotation_done_tx
                    .send(())
                    .map_err(|error| CoreError::Storage(error.to_string()))?;
                result
            });
            let attempted = attempt_rx.recv().is_ok();
            let rotation_waited = attempted
                && rotation_done_rx
                    .recv_timeout(std::time::Duration::from_millis(100))
                    .is_err();
            release_tx
                .send(())
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            let signed = signing
                .join()
                .map_err(|_| CoreError::Storage("signing thread panicked".to_owned()))?;
            let rotation_result = rotation
                .join()
                .map_err(|_| CoreError::Storage("rotation thread panicked".to_owned()))?;
            if !attempted {
                return Err(CoreError::Storage("rotation never attempted".to_owned()));
            }
            Ok((signed, rotation_result, rotation_waited))
        })?;
    let signed = signed?;
    assert!(matches!(
        rotation_result,
        Err(CoreError::ErasureContainmentUnavailable)
    ));
    assert!(rotation_waited);
    assert_rotated_registry_and_signed_event(path, &rotated, timeline.id(), signed)
}

fn assert_rotated_registry_and_signed_event(
    path: &str,
    rotated: &KeyRegistryStateV1,
    timeline_id: pos_core::TimelineId,
    signed: Event,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut resumed_rotation_store = SqliteStore::open(path)?;
    resumed_rotation_store
        .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    resumed_rotation_store.save_key_registry(rotated)?;
    let mut reopened = SqliteStore::open(path)?;
    reopened.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let persisted = reopened.load_key_registry()?.ok_or("missing registry")?;
    assert_eq!(&persisted, rotated);
    assert_eq!(reopened.read(timeline_id, SeqRange::all())?, vec![signed]);
    Ok(())
}

#[test]
fn sqlite_destruction_winning_first_rejects_late_signing() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("destroy-before-sign.sqlite");
    let path = path.to_str().ok_or("temporary SQLite path is not UTF-8")?;
    let (material, identity, registry) = signing_fixture()?;
    let mut setup = SqliteStore::open(path)?;
    setup.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    setup.save_key_registry(&registry)?;
    let timeline = setup.create_timeline("destroy-before-sign")?;
    drop(setup);

    let mut destroyer = SqliteStore::open(path)?;
    let request = KeyDestructionRequestV1::new(
        identity,
        material.material_digest(),
        pos_core::Hash::from_bytes([91; 32]),
    );
    let (_, pending) =
        std::thread::spawn(move || destroyer.begin_key_registry_destruction(request))
            .join()
            .map_err(|_| CoreError::Storage("destruction thread panicked".to_owned()))??;
    let mut signer = SqliteStore::open(path)?;
    signer.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let unexpected_calls = std::cell::Cell::new(0);
    let mut not_called =
        |_: &mut KeyRegistryStateV1, _: &TimelineEventEnvelopeV1, _: &CanonicalBytes| {
            unexpected_calls.set(unexpected_calls.get() + 1);
            Err(CoreError::Storage("signer must not run".to_owned()))
        };
    assert!(signer
        .append_timeline_signed_authorized(
            timeline.id(),
            &pending,
            draft(b"too-late"),
            identity,
            material.material_digest(),
            material.public_verification_key(),
            &mut not_called,
        )
        .is_err());
    assert!(signer.read_own(timeline.id(), SeqRange::all())?.is_empty());
    assert_eq!(unexpected_calls.get(), 0);
    Ok(())
}

#[test]
fn sqlite_existing_ledger_initialization_requires_bound_inventory(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = SqliteStore::open_in_memory()?;
    store.create_timeline("existing-ledger")?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_fail_closed()))?;

    assert!(matches!(
        store.initialize_timeline_with_key_registry("existing-ledger", &KeyRegistryStateV1::new()),
        Err(CoreError::ErasureContainmentUnavailable)
    ));
    assert!(store.load_key_registry()?.is_none());
    Ok(())
}
