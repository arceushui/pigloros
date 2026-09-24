#![cfg(feature = "sqlite")]

use std::sync::Arc;

use pos_core::{
    CanonicalBytes, CoreError, EntityId, ErasureContainmentGateV1, Event, EventDraft, EventStore,
    Hash, KeyDestructionRequestV1, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1,
    Kind, Seq, SeqRange, Signature, TimelineEventEnvelopeErrorV1, TimelineEventEnvelopeV1,
};
use pos_crypto::{
    key_roles::{sign_timeline_event_for_registered_role, SigningKeyMaterial},
    signing::{generate_keypair, verifying_key_from_public_key},
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
    rotation_result?;
    assert!(rotation_waited);
    let mut reopened = SqliteStore::open(path)?;
    reopened.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let persisted = reopened.load_key_registry()?.ok_or("missing registry")?;
    assert_eq!(persisted, rotated);
    assert_eq!(reopened.read(timeline.id(), SeqRange::all())?, vec![signed]);
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
